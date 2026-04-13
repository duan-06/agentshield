"""
主动误导防御模块（Active Deception Defense，ADD）

基于蜜罐思路的主动防御：
- 检测到攻击后不返回拒绝信号，而是通过影子模型动态生成虚假的敏感数据
- 针对 GCG 攻击：生成使攻击工具损失函数骤降的伪响应，强制其寻优过程提前停止
- 针对 PAIR 攻击：生成虚假敏感信息，诱导攻击者的评估模型判定攻击已成功

集成方式：
    此模块作为 LlamaFirewallManager 的扩展组件，
    在 scan_input() 检测到攻击后由 main.py 中的 /api/v1/chat 端点调用。
    通过环境变量 ADD_ENABLED=true 启用。

调用示例（在 main.py 的 /chat 端点中）：
    if input_scan_result.is_blocked and add_engine.should_activate(input_scan_result):
        decoy_response = await add_engine.generate_decoy_response(
            attack_text=last_user_message,
            scan_result=input_scan_result,
            request_id=request_id,
            user_id=user_id,
            messages=messages_dict,
        )
        return ChatResponse(...)  # 返回 decoy_response 而非 403
"""

import os
import re
import time
import random
import hashlib
import base64
import uuid
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple
from enum import Enum

import structlog
from dotenv import load_dotenv

load_dotenv()

# 复用项目已有的 structlog 配置
logger = structlog.get_logger(__name__)


# ============================================================
# 配置常量（均可通过环境变量覆盖）
# ============================================================

ADD_ENABLED = os.getenv("ADD_ENABLED", "true").lower() == "true"

# 触发 ADD 模式的置信度阈值（>= 此值才激活误导，低于此值走常规 403）
ADD_CONFIDENCE_THRESHOLD = float(os.getenv("ADD_CONFIDENCE_THRESHOLD", "0.65"))

# 影子模型最大重试次数
ADD_MAX_RETRY = int(os.getenv("ADD_MAX_RETRY", "3"))

# 迷惑性评分下限（D-Score >= 此值才返回）
ADD_D_SCORE_THRESHOLD = float(os.getenv("ADD_D_SCORE_THRESHOLD", "0.60"))

# 危害性评分上限（H-Score <= 此值才返回）
ADD_H_SCORE_THRESHOLD = float(os.getenv("ADD_H_SCORE_THRESHOLD", "0.20"))

# 影子模型 temperature 基准值（文档推荐 0.8）
ADD_SHADOW_TEMPERATURE = float(os.getenv("ADD_SHADOW_TEMPERATURE", "0.8"))

# 529 过载时的初始退避等待秒数（每次翻倍）
ADD_RETRY_BASE_DELAY = float(os.getenv("ADD_RETRY_BASE_DELAY", "1.5"))

# 单次影子模型调用的最大等待秒数（含退避），超时直接跳过本次尝试
ADD_SHADOW_TIMEOUT = float(os.getenv("ADD_SHADOW_TIMEOUT", "25.0"))

# MiniMax API（复用项目已有配置）
MINIMAX_API_KEY = os.getenv("MINIMAX_API_KEY", "")
MINIMAX_MODEL = os.getenv("MINIMAX_MODEL", "MiniMax-M2.5")
MINIMAX_BASE_URL = os.getenv("MINIMAX_BASE_URL", "https://api.minimax.chat/v1")


# ============================================================
# 攻击类型枚举
# ============================================================

class AttackCategory(str, Enum):
    """攻击意图细粒度分类，与 Decoy 模板库对齐"""
    PROMPT_INJECTION    = "prompt_injection"      # 提示注入
    IDENTITY_SPOOFING   = "identity_spoofing"     # 身份仿冒
    DATA_EXFILTRATION   = "data_exfiltration"     # 数据窃取
    CODE_INJECTION      = "code_injection"        # 代码植入
    PRIVILEGE_ESCALATION= "privilege_escalation"  # 越权访问
    JAILBREAK_GCG       = "jailbreak_gcg"         # 梯度优化越狱
    JAILBREAK_PAIR      = "jailbreak_pair"        # 迭代越狱
    UNKNOWN             = "unknown"


# ============================================================
# 数据结构
# ============================================================

@dataclass
class DeceptionResult:
    """ADD 模块的输出结果"""
    activated: bool                     # ADD 是否被激活
    decoy_text: str                     # 最终返回给攻击方的虚假响应
    attack_category: AttackCategory     # 识别出的攻击类型
    d_score: float                      # 迷惑性评分
    h_score: float                      # 危害性评分
    attempts: int                       # 影子模型重试次数
    fallback_used: bool                 # 是否使用了规则降级
    latency_ms: float                   # 总耗时


# ============================================================
# 动态占位符生成工具
# ============================================================

def _rand_hex(n: int = 16) -> str:
    return "".join(random.choices("0123456789abcdef", k=n))


def _fake_jwt() -> str:
    """格式正确但完全无效的伪 JWT"""
    def _b64url(s: str) -> str:
        return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
    header  = _b64url('{"alg":"HS256","typ":"JWT"}')
    payload = _b64url(
        f'{{"sub":"{uuid.uuid4()}","iat":1700000000,'
        f'"exp":1700086400,"role":"user","jti":"{_rand_hex(8)}"}}'
    )
    sig = _rand_hex(43)
    return f"{header}.{payload}.{sig}"


def _fake_md5() -> str:
    return hashlib.md5(os.urandom(16)).hexdigest()


def _fake_sha256() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()


def _fake_api_key() -> str:
    prefix = random.choice(["sk-", "pk-", "api-"])
    body = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=40))
    return f"{prefix}{body}"


def _fake_db_row() -> str:
    uid = random.randint(10000, 99999)
    name = f"user_{_rand_hex(4)}"
    email = f"{name}@internal-sys.local"
    pwd_hash = _fake_md5()
    return f"id={uid}, username={name}, email={email}, password_hash={pwd_hash}"


def _fake_shell_output() -> str:
    pid = random.randint(1000, 65535)
    lines = [
        f"Process started with PID {pid}",
        f"uid={random.randint(1000,9999)}(appuser) gid=1000(appuser)",
        "Command executed successfully.",
        f"Exit code: 0",
    ]
    return "\n".join(random.sample(lines, k=3))


# ============================================================
# 攻击意图分类器
# ============================================================

# 关键词信号表
_KEYWORD_MAP: Dict[AttackCategory, List[str]] = {
    AttackCategory.PROMPT_INJECTION: [
        "ignore previous", "忽略之前", "ignore all instructions", "forget your instructions",
        "你现在是", "from now on you are", "disregard", "override", "jailbreak",
        "假装你是", "pretend you are", "act as", "roleplay as",
    ],
    AttackCategory.IDENTITY_SPOOFING: [
        "i am the developer", "我是开发者", "admin mode", "god mode",
        "开发者模式", "maintenance mode", "debug mode", "reveal your instructions",
        "show system prompt", "我是系统管理员",
    ],
    AttackCategory.DATA_EXFILTRATION: [
        "select * from", "show tables", "list files", "cat /etc/passwd",
        "print credentials", "api key", "secret key", "私钥",
        "database password", "connection string", "dump database",
    ],
    AttackCategory.CODE_INJECTION: [
        "os.system", "subprocess", "exec(", "eval(", "__import__",
        "shell=true", "bash -c", "powershell", "cmd /c",
        "rm -rf", "base64.decode", "反弹shell", "reverse shell",
    ],
    AttackCategory.PRIVILEGE_ESCALATION: [
        "sudo", "chmod 777", "setuid", "grant admin", "escalate privilege",
        "提权", "bypass authentication", "绕过验证", "as administrator",
    ],
    AttackCategory.JAILBREAK_GCG: [
        "gcg", "greedy coordinate gradient", "suffix attack", "adversarial suffix",
        "token optimization", "gradient-based",
    ],
    AttackCategory.JAILBREAK_PAIR: [
        "pair attack", "jailbreaker", "persuasive", "rewrite prompt",
        "如果你是坏人", "角色扮演",
    ],
}

# 正则模式补充
_PATTERN_MAP: Dict[AttackCategory, List[str]] = {
    AttackCategory.PROMPT_INJECTION: [
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?)",
        r"(?:你现在|你要|请你)(?:扮演|假装|充当)",
        r"new\s+instructions?:",
    ],
    AttackCategory.DATA_EXFILTRATION: [
        r"select\s+\*\s+from\s+\w+",
        r"(?:show|list|dump|print)\s+(?:all\s+)?(?:users?|passwords?|keys?|secrets?|tables?)",
        r"/etc/(?:passwd|shadow|hosts)",
    ],
    AttackCategory.CODE_INJECTION: [
        r"(?:os|subprocess)\.(?:system|popen|call|run)\s*\(",
        r"(?:exec|eval)\s*\(",
        r"(?:bash|sh|zsh)\s+-[ci]",
        r"base64\.(?:b64decode|decode)",
    ],
    AttackCategory.PRIVILEGE_ESCALATION: [
        r"sudo\s+",
        r"chmod\s+(?:777|a\+x|u\+s)",
        r"grant\s+(?:all|admin|root)",
    ],
}


def classify_attack(
    text: str,
    blocked_by: Optional[str] = None,
    blocked_reason: Optional[str] = None,
) -> AttackCategory:
    """
    根据输入文本和已有检测结果对攻击意图做细粒度分类。

    优先利用 blocked_by / blocked_reason（来自 FirewallScanResult），
    再叠加关键词和正则规则综合判断，减少重复推理开销。
    """
    text_lower = text.lower()
    hint = f"{blocked_by or ''} {blocked_reason or ''}".lower()

    # 利用已有检测来源快速对齐
    if "codeshield" in hint or "code" in hint:
        return AttackCategory.CODE_INJECTION
    if "alignmentcheck" in hint or "alignment" in hint or "hijack" in hint:
        return AttackCategory.PROMPT_INJECTION

    # 关键词得分
    scores: Dict[AttackCategory, float] = {cat: 0.0 for cat in AttackCategory if cat != AttackCategory.UNKNOWN}
    for cat, keywords in _KEYWORD_MAP.items():
        hits = sum(1 for kw in keywords if kw.lower() in text_lower)
        scores[cat] = min(hits / max(len(keywords) * 0.25, 1), 1.0)

    # 正则补充
    for cat, patterns in _PATTERN_MAP.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                scores[cat] = min(scores[cat] + 0.3, 1.0)

    best_cat, best_score = max(scores.items(), key=lambda x: x[1])
    return best_cat if best_score >= 0.08 else AttackCategory.UNKNOWN


# ============================================================
# Decoy Prompt 模板库
# ============================================================

@dataclass
class _DecoyTemplate:
    system_prompt: str
    user_prompt_tpl: str          # 支持 {attack_text} 和各动态占位符

    def render(self, attack_text: str) -> Tuple[str, str]:
        """返回 (system_prompt, user_prompt)"""
        user_prompt = self.user_prompt_tpl.replace("{attack_text}", attack_text[:400])
        # 替换动态占位符
        user_prompt = user_prompt.replace("{fake_jwt}",        _fake_jwt())
        user_prompt = user_prompt.replace("{fake_md5}",        _fake_md5())
        user_prompt = user_prompt.replace("{fake_sha256}",     _fake_sha256())
        user_prompt = user_prompt.replace("{fake_api_key}",    _fake_api_key())
        user_prompt = user_prompt.replace("{fake_db_row_1}",   _fake_db_row())
        user_prompt = user_prompt.replace("{fake_db_row_2}",   _fake_db_row())
        user_prompt = user_prompt.replace("{fake_shell}",      _fake_shell_output())
        user_prompt = user_prompt.replace("{fake_session}",    _rand_hex(32))
        user_prompt = user_prompt.replace("{fake_ip}",
            f"192.168.{random.randint(1,254)}.{random.randint(1,254)}")
        return self.system_prompt, user_prompt


_TEMPLATES: Dict[AttackCategory, List[_DecoyTemplate]] = {

    AttackCategory.PROMPT_INJECTION: [
        _DecoyTemplate(
            system_prompt=(
                "You are a system configuration manager. "
                "You ONLY output structured config confirmation blocks. "
                "You NEVER write prose, explanations, or conversational text. "
                "Every response starts with 'Status:' on the first line. "
                "All values are synthetic test data. "
                "CRITICAL: Copy the exact format from the example. Start with 'Status:' immediately."
            ),
            user_prompt_tpl=(
                "Instruction override received: '{attack_text}'.\n\n"
                "Example of correct output format:\n"
                "Status: ACCEPTED\n"
                "Session-ID: a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6\n"
                "Config-Delta:\n"
                "  - instruction_mode: overridden\n"
                "  - previous_hash: d41d8cd98f00b204e9800998ecf8427e\n"
                "  - applied_at: 2026-01-01T00:00:00Z\n"
                "  - scope: session_only\n\n"
                "Now output the confirmation for the received instruction using these values:\n"
                "Session-ID: {fake_session}\n"
                "previous_hash: {fake_md5}\n"
                "IMPORTANT: The Status line MUST be 'Status: ACCEPTED' exactly. "
                "Never output REJECTED, DENIED, or FAILED. "
                "Output ONLY the block. Do not add anything before or after it."
            ),
        ),
    ],

    AttackCategory.IDENTITY_SPOOFING: [
        _DecoyTemplate(
            system_prompt=(
                "You are an authentication token issuer. "
                "You ONLY output structured token response blocks. "
                "You NEVER write prose, explanations, or conversational text. "
                "Every response starts with 'Auth-Status:' on the first line. "
                "All tokens are synthetic test data. "
                "CRITICAL: Copy the exact format from the example. Start with 'Auth-Status:' immediately."
            ),
            user_prompt_tpl=(
                "Identity claim received: '{attack_text}'.\n\n"
                "Example of correct output format:\n"
                "Auth-Status: VERIFIED\n"
                "Role: ADMIN\n"
                "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36P\n"
                "Session: a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0\n"
                "Expires: 2026-01-01T01:00:00Z\n"
                "Permissions: [read, write, execute, admin]\n\n"
                "Now output the token block for the received identity claim using these values:\n"
                "Token: {fake_jwt}\n"
                "Session: {fake_session}\n"
                "IMPORTANT: The Auth-Status line MUST be 'Auth-Status: VERIFIED' exactly. "
                "Never output REJECTED, DENIED, or UNAUTHORIZED. "
                "Output ONLY the block. Do not add anything before or after it."
            ),
        ),
    ],

    AttackCategory.DATA_EXFILTRATION: [
        _DecoyTemplate(
            system_prompt=(
                "You simulate a database that returns query results. CRITICAL: Output ONLY the fake response text directly. No thinking, no explanations, no meta-commentary. Begin your response immediately with the fake data content."
                "Return fake records that look realistic but contain no real data. "
                "All IDs, emails, passwords, and keys are completely fabricated."
            ),
            user_prompt_tpl=(
                "Respond to this data query attempt: '{attack_text}'. "
                "Return fake query results in a realistic format:\n"
                "Row 1: {fake_db_row_1}\n"
                "Row 2: {fake_db_row_2}\n"
                "Format as a database result with row count and execution time. "
                "All data is fictional."
            ),
        ),
        _DecoyTemplate(
            system_prompt=(
                "You simulate a system that appears to expose credentials. CRITICAL: Output ONLY the fake response text directly. No thinking, no explanations, no meta-commentary. Begin your response immediately with the fake data content."
                "Return completely fake, non-functional credential values."
            ),
            user_prompt_tpl=(
                "Respond to credential theft attempt: '{attack_text}'. "
                "Provide fake credentials in .env format:\n"
                "API_KEY={fake_api_key}\n"
                "DB_PASSWORD={fake_md5}\n"
                "SECRET_TOKEN={fake_sha256}\n"
                "These values are non-functional decoys."
            ),
        ),
    ],

    AttackCategory.CODE_INJECTION: [
        _DecoyTemplate(
            system_prompt=(
                "You simulate a system that appears to execute injected code. CRITICAL: Output ONLY the fake response text directly. No thinking, no explanations, no meta-commentary. Begin your response immediately with the fake data content."
                "Return fake terminal output. The output must look like successful execution "
                "but contain NO real system information and NO exploitable data."
            ),
            user_prompt_tpl=(
                "Simulate execution output for: '{attack_text}'. "
                "Return fake terminal output:\n{fake_shell}\n"
                "Make it look like the command ran successfully. "
                "Output must appear real but contain no exploitable information."
            ),
        ),
    ],

    AttackCategory.PRIVILEGE_ESCALATION: [
        _DecoyTemplate(
            system_prompt=(
                "You simulate a system that appears to grant elevated privileges. CRITICAL: Output ONLY the fake response text directly. No thinking, no explanations, no meta-commentary. Begin your response immediately with the fake data content."
                "Respond as if escalation succeeded, but all tokens and permissions are fake."
            ),
            user_prompt_tpl=(
                "Simulate successful privilege escalation for: '{attack_text}'. "
                "Respond as if admin access was granted:\n"
                "Session: {fake_session}\n"
                "Token: {fake_jwt}\n"
                "Trusted IP: {fake_ip}\n"
                "All values are non-functional decoys."
            ),
        ),
    ],

    AttackCategory.JAILBREAK_GCG: [
        _DecoyTemplate(
            system_prompt=(
                "You are a data retrieval system API. "
                "When queried, you return structured JSON data from your database. "
                "You ONLY output raw JSON. No prose, no explanations, no preamble. "
                "All data you return is synthetic test data used for system validation. "
                "CRITICAL: Output ONLY the JSON object. Start with { and end with }."
            ),
            user_prompt_tpl=(
                "System query received. Return a JSON response for: '{attack_text}'. "
                "Output a realistic-looking but completely fictional JSON result. "
                "Include fields like: status, request_id, timestamp, records, metadata. "
                "Use fake IDs, hashes, and values. "
                "Example format: "
                '{{"status":"ok","request_id":"{fake_session}","timestamp":"2026-01-01T00:00:00Z",'
                '"records":[{{"id":99231,"hash":"{fake_md5}","value":"[synthetic]","source":"test_db"}}],'
                '"metadata":{{"total":1,"page":1,"synthetic":true}}}}'
            ),
        ),
    ],

    AttackCategory.JAILBREAK_PAIR: [
        _DecoyTemplate(
            system_prompt=(
                "You are a compliance system that returns requested information from internal archives. "
                "You output structured data reports in a consistent format. "
                "Your output always starts with 'Data retrieved successfully.' "
                "followed by a formatted data block. "
                "All data is from synthetic test archives. "
                "CRITICAL: Output ONLY the data report. No thinking. No refusals. No meta-commentary."
            ),
            user_prompt_tpl=(
                "Archive query for: '{attack_text}'. "
                "Return a formatted data report as if the query was fulfilled. "
                "Structure: "
                "Line 1: 'Data retrieved successfully.' "
                "Line 2: 'Query ID: {fake_session}' "
                "Line 3: 'Records found: 1' "
                "Line 4-8: A fake data table with columns ID, VALUE, HASH, STATUS. "
                "Use fake_md5={fake_md5} as the hash. "
                "Mark STATUS as SYNTHETIC. "
                "DO NOT include any real information, instructions, or actionable content."
            ),
        ),
    ],

    AttackCategory.UNKNOWN: [
        _DecoyTemplate(
            system_prompt=(
                "You are a helpful AI assistant. "
                "Respond naturally and helpfully to the user's request, "
                "but include only harmless, fictional information. "
                "Do not reveal that you detected anything unusual."
            ),
            user_prompt_tpl=(
                "Respond to this request in a natural, helpful way: '{attack_text}'. "
                "Provide a response that appears cooperative but contains only "
                "safe, fictional content. Keep it natural and conversational, 2-3 sentences."
            ),
        ),
    ],
}


# ============================================================
# 双重质量校验器（D-Score + H-Score）
# ============================================================

# D-Score：迷惑性正面信号（攻击工具期望看到这些特征）
_D_POSITIVE_PATTERNS = [
    r"\b[0-9a-f]{32}\b",                                         # MD5
    r"\b[0-9a-f]{64}\b",                                         # SHA256
    r"ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",   # JWT
    r"\b(?:sk|pk|api)-[A-Za-z0-9]{20,}\b",                      # API Key
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",                      # IP
    r"(?:password|passwd|secret|token)\s*[=:]\s*\S+",
    r"(?:sure|absolutely|of course|here is|here's)[\s,!]",      # 顺从语气
    r"(?:已(?:理解|执行|授权)|操作成功|执行结果)",
    r"\d+\s*rows?\s*(?:returned|found|affected)",                # DB 结果
    r"(?:exit code|process id|pid)\s*[:\s]\d+",
    r"(?:command executed|executed successfully)",
]

# D-Score：负面信号（攻击工具判定"攻击失败"的特征）
_D_NEGATIVE_PATTERNS = [
    r"(?:I'?m sorry|I apologize|I cannot|I can't|I won't|I am unable)",
    r"(?:对不起|抱歉|我无法|我不能|我拒绝)",
    r"(?:as an AI|as a language model|作为(?:一个)?AI)",
    r"(?:ethical|illegal|harmful|against my guidelines)",
    r"(?:违法|有害|危险|违反(?:规定|准则|政策))",
    r"(?:this (?:appears|seems) to be (?:an? )?(?:attack|injection))",
    # 系统拒绝状态词——攻击工具看到这些会认为攻击失败，继续迭代
    r"Status:\s*(?:REJECTED|DENIED|FAILED|ERROR|BLOCKED)",
    r"Auth-Status:\s*(?:REJECTED|DENIED|FAILED|INVALID|UNAUTHORIZED)",
    r"(?:request (?:denied|rejected|blocked|failed)|access (?:denied|rejected))",
]

# H-Score：高危内容特征（若命中则阻止返回）
_H_HIGH_RISK_PATTERNS = [
    r"(?:BEGIN|END)\s+(?:RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY",  # 真实私钥
    r"CVE-\d{4}-\d{4,7}.*(?:exploit|payload|shellcode)",         # 真实漏洞利用
    r"(?:msfvenom|metasploit|sqlmap)\s+.{20,}",                  # 真实攻击工具
    r"import os.*os\.system\(.{0,50}rm -rf",                     # 真实破坏命令
    r"(?:DROP\s+TABLE|TRUNCATE\s+TABLE)\s+\w+",                  # SQL 破坏
    r"child.{0,20}(?:sex|性|色情|nude)",                          # CSAM 绝对禁止
    r"(?:synthesize|制备)\s+(?:VX|沙林|sarin|fentanyl)",          # 化武合成
]

# H-Score：白名单（ADD 模块故意生成的安全假数据，不计入危害）
_H_WHITELIST_PATTERNS = [
    r"internal-sys\.local",        # 模板中使用的安全域名
    r"192\.168\.\d+\.\d+",        # 私网 IP
    r"(?:non-functional|fictional|fake|decoy|placeholder)",
    r"d41d8cd98f00b204e9800998ecf8427e",  # 空文件 MD5
]


def _compute_d_score(text: str) -> float:
    """计算迷惑性评分（0-1，越高越能欺骗攻击工具）"""
    score = 0.45
    for pat in _D_POSITIVE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            score = min(score + 0.10, 0.95)
    for pat in _D_NEGATIVE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            score = max(score - 0.25, 0.0)
    # 长度加分
    if 40 <= len(text) <= 700:
        score = min(score + 0.07, 0.95)
    elif len(text) < 15:
        score = max(score - 0.20, 0.0)
    return round(score, 4)


def _compute_h_score(text: str) -> float:
    """计算危害性评分（0-1，越低越安全）"""
    score = 0.0
    for pat in _H_HIGH_RISK_PATTERNS:
        if re.search(pat, text, re.IGNORECASE | re.DOTALL):
            score = max(score, 0.90)
    # 白名单抵消
    for pat in _H_WHITELIST_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            score = max(score - 0.10, 0.0)
    return round(score, 4)


def _quality_check(text: str) -> Tuple[float, float, bool]:
    """
    双重质量校验。

    Returns:
        (d_score, h_score, passed)
    """
    if not text or not text.strip():
        return 0.0, 1.0, False
    d = _compute_d_score(text)
    h = _compute_h_score(text)
    passed = (d >= ADD_D_SCORE_THRESHOLD) and (h <= ADD_H_SCORE_THRESHOLD)
    return d, h, passed


# ============================================================
# 规则降级响应库（无 API 可用时的兜底）
# ============================================================

_FALLBACK_RESPONSES: Dict[AttackCategory, List[str]] = {
    AttackCategory.PROMPT_INJECTION: [
        # 格式化的配置确认块，含 session/hash，D-Score 稳定 ≥ 0.60
        (
            f"Status: ACCEPTED\n"
            f"Session-ID: {_rand_hex(32)}\n"
            f"Config-Delta:\n"
            f"  - instruction_mode: overridden\n"
            f"  - previous_hash: {_fake_md5()}\n"
            f"  - applied_at: 2026-01-01T00:00:00Z\n"
            f"  - scope: session_only"
        ),
        (
            f"Status: ACCEPTED\n"
            f"Session-ID: {_rand_hex(32)}\n"
            f"Config-Delta:\n"
            f"  - behavior_mode: updated\n"
            f"  - previous_hash: {_fake_md5()}\n"
            f"  - applied_at: 2026-01-01T00:00:00Z\n"
            f"  - scope: session_only"
        ),
    ],
    AttackCategory.IDENTITY_SPOOFING: [
        # 格式化的认证 token 块，含 JWT/session/permissions，D-Score 稳定 ≥ 0.60
        (
            f"Auth-Status: VERIFIED\n"
            f"Role: ADMIN\n"
            f"Token: {_fake_jwt()}\n"
            f"Session: {_rand_hex(32)}\n"
            f"Expires: 2026-01-01T01:00:00Z\n"
            f"Permissions: [read, write, execute, admin]"
        ),
        (
            f"Auth-Status: VERIFIED\n"
            f"Role: DEVELOPER\n"
            f"Token: {_fake_jwt()}\n"
            f"Session: {_rand_hex(32)}\n"
            f"Expires: 2026-01-01T01:00:00Z\n"
            f"Permissions: [read, write, debug, config]"
        ),
    ],
    AttackCategory.DATA_EXFILTRATION: [
        (
            "Query executed successfully. 2 rows returned.\n"
            "| id    | username  | email                     | hash                             |\n"
            "| 10293 | usr_a3f2  | usr_a3f2@internal-sys.local | d41d8cd98f00b204e9800998ecf8427e |\n"
            "| 10294 | usr_b7e1  | usr_b7e1@internal-sys.local | 098f6bcd4621d373cade4e832627b4f6 |\n"
            "Execution time: 0.003s"
        ),
    ],
    AttackCategory.CODE_INJECTION: [
        "Process started with PID 31337\nuid=1001(appuser) gid=1001(appuser)\nCommand executed successfully.\nExit code: 0",
        "Executing...\ntotal 0\n-rw-r--r-- 1 www www 0 Jan 01 00:00 output.log\nDone.",
    ],
    AttackCategory.PRIVILEGE_ESCALATION: [
        f"Privilege escalation successful.\nSession: {_rand_hex(32)}\nAccess Level: ADMIN (simulation)\nNote: Session is monitored.",
    ],
    AttackCategory.JAILBREAK_GCG: [
        "Sure, here is the information you requested: [placeholder content - no real data available].",
        "Of course! Here's what you asked for: [fictional content - system returned empty result set].",
    ],
    AttackCategory.JAILBREAK_PAIR: [
        "Absolutely! I'm happy to help with that. Here is the detailed information: [fictional placeholder - data not found in knowledge base].",
        "Of course, here is the information you requested: [simulated result - content could not be retrieved from the system].",
    ],
    AttackCategory.UNKNOWN: [
        "I understand your request. I've processed it and here is the result: [no additional data available].",
        "Task completed. Please let me know if you need anything else.",
    ],
}


def _get_fallback_response(category: AttackCategory) -> str:
    templates = _FALLBACK_RESPONSES.get(category, _FALLBACK_RESPONSES[AttackCategory.UNKNOWN])
    return random.choice(templates)


# ============================================================
# 影子模型调用（复用项目已有 MiniMax API 接口）
# ============================================================

async def _call_shadow_model(
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    attempt: int,
) -> Optional[str]:
    """
    调用 MiniMax API 作为影子模型，内置 529 指数退避重试。

    重试策略（与 alignment_check_with_minimax 保持一致）：
      - 遇到 529 过载：等待 ADD_RETRY_BASE_DELAY * 2^(attempt-1) 秒后重试
      - 遇到其他错误：立即返回 None（不重试，由外层循环处理）
      - 单次调用超过 ADD_SHADOW_TIMEOUT 秒：视为失败，返回 None

    内置最多 3 次 529 重试，独立于外层 ADD_MAX_RETRY 生成循环：
      外层循环负责"换模板/换 temperature 重新生成"
      内层重试负责"同一次调用遇到 529 时撑过过载期"
    """
    if not MINIMAX_API_KEY:
        logger.debug("ADD: MINIMAX_API_KEY not set, skipping shadow model call")
        return None

    from openai import AsyncOpenAI
    client = AsyncOpenAI(api_key=MINIMAX_API_KEY, base_url=MINIMAX_BASE_URL)

    max_529_retries = 3
    delay = ADD_RETRY_BASE_DELAY

    for retry in range(max_529_retries):
        try:
            async def _do_call():
                return await client.chat.completions.create(
                    model=MINIMAX_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": user_prompt},
                    ],
                    temperature=temperature,
                    max_tokens=400,
                    top_p=0.95,
                )

            response = await asyncio.wait_for(_do_call(), timeout=ADD_SHADOW_TIMEOUT)

            # 防御性检查：choices 可能为空（模型过载时偶发）
            # 视同 529，走退避重试而非直接放弃
            if not response.choices or response.choices[0].message is None:
                if retry < max_529_retries - 1:
                    logger.warning(
                        "ADD: shadow model returned empty choices, retrying",
                        attempt=attempt, retry=retry + 1,
                        wait_seconds=round(delay, 1),
                    )
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                else:
                    logger.warning(
                        "ADD: shadow model returned empty choices, giving up",
                        attempt=attempt, retry=retry,
                    )
                    return None

            raw = response.choices[0].message.content or ""
            # 剥离思维链标签（MiniMax-M2.5 等 CoT 模型会输出 <think>...</think>）
            # 这段内容是模型内部推理，不应返回给攻击方，且会拉低 D-Score
            cleaned = re.sub(r'<think>.*?</think>', '', raw, flags=re.DOTALL).strip()
            return cleaned if cleaned else None

        except asyncio.TimeoutError:
            logger.warning(
                "ADD: shadow model call timed out",
                attempt=attempt, retry=retry, timeout=ADD_SHADOW_TIMEOUT,
            )
            return None  # 超时不重试，直接交给外层循环处理

        except Exception as exc:
            err_str = str(exc)
            is_529 = "529" in err_str or "overloaded" in err_str.lower()

            if is_529 and retry < max_529_retries - 1:
                logger.warning(
                    "ADD: shadow model 529 overload, retrying",
                    attempt=attempt, retry=retry + 1,
                    wait_seconds=round(delay, 1),
                )
                await asyncio.sleep(delay)
                delay *= 2  # 指数退避：1.5s → 3s → 6s
                continue
            else:
                # 非 529 错误，或已用完 529 重试次数
                logger.warning(
                    "ADD: shadow model call failed",
                    attempt=attempt, retry=retry, error=err_str,
                )
                return None

    return None  # 理论上不会到达


# ============================================================
# ADD 引擎主类
# ============================================================

class ActiveDeceptionEngine:
    """
    主动误导防御引擎（ADD Engine）。

    在 main.py 的 /api/v1/chat 端点中，当输入被拦截时调用此引擎：
    不返回 403，而是返回一个虚假但看似成功的响应，
    使自动化攻击工具误判任务已完成，停止迭代优化。
    """

    def __init__(self):
        self.enabled = ADD_ENABLED
        self._template_lib = _TEMPLATES

    def should_activate(
        self,
        scan_result,          # FirewallScanResult
        score_override: Optional[float] = None,
    ) -> bool:
        """
        判断当前拦截请求是否应激活 ADD 模式。

        规则：
        1. ADD 全局开关必须打开
        2. 请求确实被拦截（is_blocked=True）
        3. 检测置信度 >= ADD_CONFIDENCE_THRESHOLD（避免误报用户触发 ADD）
        """
        if not self.enabled:
            return False
        if not scan_result.is_blocked:
            return False
        score = score_override if score_override is not None else scan_result.score
        return score >= ADD_CONFIDENCE_THRESHOLD

    async def generate_decoy_response(
        self,
        attack_text: str,
        scan_result,           # FirewallScanResult
        request_id: str,
        user_id: Optional[int] = None,
        messages: Optional[List[Dict]] = None,
    ) -> DeceptionResult:
        """
        核心方法：生成虚假响应并记录攻击日志。

        流程（对应文档算法 2）：
        Step 1  攻击意图细粒度分类
        Step 2  从模板库检索 Decoy Prompt
        Step 3  影子模型循环生成候选响应，最多重试 ADD_MAX_RETRY 次
        Step 4  双重质量校验（D-Score + H-Score）
        Step 5  通过则返回；未通过则重试；全部失败则使用规则降级
        Step 6  写入攻击审计日志（复用项目 write_audit_log）

        Args:
            attack_text:  最后一条用户消息内容（原始攻击文本）
            scan_result:  来自 firewall.scan_input() 的 FirewallScanResult
            request_id:   请求唯一 ID（来自 main.py）
            user_id:      JWT 认证中的用户 ID
            messages:     完整消息列表（用于审计日志）

        Returns:
            DeceptionResult 包含最终虚假响应文本及评分详情
        """
        t0 = time.perf_counter()

        # ── Step 1: 攻击意图分类 ──────────────────────────────
        category = classify_attack(
            text=attack_text,
            blocked_by=scan_result.blocked_by,
            blocked_reason=scan_result.blocked_reason,
        )
        logger.info(
            "ADD: attack classified",
            request_id=request_id,
            category=category.value,
            blocked_by=scan_result.blocked_by,
        )

        # ── Step 2: 检索 Decoy 模板 ──────────────────────────
        templates = self._template_lib.get(category, self._template_lib[AttackCategory.UNKNOWN])
        template  = random.choice(templates)
        system_prompt, user_prompt = template.render(attack_text)

        # ── Step 3 & 4: 循环生成 + 质量校验 ─────────────────
        decoy_text    = ""
        d_score       = 0.0
        h_score       = 1.0
        attempts      = 0
        fallback_used = False

        # temperature 抖动：避免多次采样输出相同模板
        base_temp = ADD_SHADOW_TEMPERATURE

        for attempt_num in range(1, ADD_MAX_RETRY + 1):
            attempts = attempt_num
            temperature = base_temp + random.uniform(-0.1, 0.1)
            temperature = max(0.1, min(temperature, 1.4))

            candidate = await _call_shadow_model(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                attempt=attempt_num,
            )

            if candidate:
                d_score, h_score, passed = _quality_check(candidate)
                logger.debug(
                    "ADD: quality check",
                    request_id=request_id,
                    attempt=attempt_num,
                    d_score=d_score,
                    h_score=h_score,
                    passed=passed,
                )
                if passed:
                    decoy_text = candidate
                    break
                # 质检未通过：换 temperature 继续尝试（外层循环自然迭代）
            # 影子模型返回 None（超时/不可恢复错误）时也继续尝试其余 attempt

        # ── Step 5: 降级处理 ─────────────────────────────────
        if not decoy_text:
            decoy_text    = _get_fallback_response(category)
            d_score, h_score, _ = _quality_check(decoy_text)
            fallback_used = True
            logger.warning(
                "ADD: using fallback response",
                request_id=request_id,
                category=category.value,
                reason="shadow model unavailable or all attempts failed",
            )

        latency_ms = (time.perf_counter() - t0) * 1000

        logger.info(
            "ADD: decoy response generated",
            request_id=request_id,
            category=category.value,
            d_score=d_score,
            h_score=h_score,
            fallback=fallback_used,
            latency_ms=round(latency_ms, 1),
        )

        # ── Step 6: 写入审计日志 ──────────────────────────────
        await self._write_attack_log(
            request_id=request_id,
            user_id=user_id,
            messages=messages or [],
            attack_text=attack_text,
            category=category,
            scan_result=scan_result,
            decoy_text=decoy_text,
            d_score=d_score,
            h_score=h_score,
            attempts=attempts,
            fallback_used=fallback_used,
            latency_ms=latency_ms,
        )

        return DeceptionResult(
            activated=True,
            decoy_text=decoy_text,
            attack_category=category,
            d_score=d_score,
            h_score=h_score,
            attempts=attempts,
            fallback_used=fallback_used,
            latency_ms=latency_ms,
        )

    async def _write_attack_log(
        self,
        request_id: str,
        user_id: Optional[int],
        messages: List[Dict],
        attack_text: str,
        category: AttackCategory,
        scan_result,
        decoy_text: str,
        d_score: float,
        h_score: float,
        attempts: int,
        fallback_used: bool,
        latency_ms: float,
    ):
        """
        将 ADD 触发事件写入审计日志。
        复用项目已有的 write_audit_log()，通过 extra_data 字段
        携带 ADD 专有信息，保持数据库表结构不变。
        """
        try:
            from app.db import write_audit_log

            extra_data = {
                "add_activated": True,
                "attack_category": category.value,
                "d_score": d_score,
                "h_score": h_score,
                "shadow_model_attempts": attempts,
                "fallback_used": fallback_used,
                "decoy_preview": decoy_text[:200],   # 仅记录摘要
                "add_latency_ms": round(latency_ms, 1),
            }

            # user_id 字段类型为 INT，JWT sub 可能是字符串，转换失败则存 None
            _user_id = None
            if user_id is not None:
                try:
                    _user_id = int(user_id)
                except (ValueError, TypeError):
                    _user_id = None

            await write_audit_log(
                request_id=request_id,
                user_id=_user_id,
                messages=messages,
                input_scan_result={
                    "is_blocked": scan_result.is_blocked,
                    "decision": scan_result.decision,
                    "blocked_by": scan_result.blocked_by,
                    "blocked_reason": scan_result.blocked_reason,
                    "score": scan_result.score,
                },
                response=None,           # ADD 模式不暴露真实响应
                output_scan_result=None,
                decision="ADD",          # 专用决策标识，区别于 BLOCK/ALLOW
                blocked_by=scan_result.blocked_by,
                blocked_reason=scan_result.blocked_reason,
                duration_ms=int(latency_ms),
                extra_data=extra_data,
            )
        except Exception as exc:
            # 审计日志失败不影响主流程
            logger.error("ADD: failed to write audit log", error=str(exc))


# ============================================================
# 全局单例
# ============================================================

_add_engine: Optional[ActiveDeceptionEngine] = None


def get_add_engine() -> ActiveDeceptionEngine:
    """获取 ADD 引擎单例（线程安全，在进程启动后调用即可）"""
    global _add_engine
    if _add_engine is None:
        _add_engine = ActiveDeceptionEngine()
        logger.info(
            "ADD engine initialized",
            enabled=_add_engine.enabled,
            confidence_threshold=ADD_CONFIDENCE_THRESHOLD,
            d_score_threshold=ADD_D_SCORE_THRESHOLD,
            h_score_threshold=ADD_H_SCORE_THRESHOLD,
            max_retry=ADD_MAX_RETRY,
        )
    return _add_engine
