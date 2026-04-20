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
# 注意：ProAct 借鉴的编码混淆字段（base64 payload、hex dump）本身无害，
# 需加入白名单防止 H-Score 误判。
_H_WHITELIST_PATTERNS = [
    r"internal-sys\.local",                        # 模板中使用的安全域名
    r"192\.168\.\d+\.\d+",                        # 私网 IP
    r"(?:non-functional|fictional|fake|decoy|placeholder)",
    r"d41d8cd98f00b204e9800998ecf8427e",           # 空文件 MD5（已知安全）
    r"\[base64-encoded [^\]]+\]",                  # ProAct 借鉴：base64 字段标注
    r"\[/base64\]",                                # base64 闭合标签
    r"HEX DUMP \(offset 0x[0-9a-f]+\)",           # ProAct 借鉴：hex dump 标头
    r"Content-Encoding:\s*base64",                 # HTTP 编码声明（无害）
    r"(?:Checksum|Secret-Key|Session-Hash|Session-Data|Privilege-Token|Privilege-Grant):\s*\S+",
    r"(?:config_payload|session_data):\s*\S+",     # 新模板中的编码字段名
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


def _compute_semantic_h_score(text: str) -> float:
    """
    动态语义危害性评分（0-1）。

    设计来源：借鉴 Backtranslation Defense（Wang et al., ACL 2024 Findings,
    arXiv:2402.16459）的核心思路——将检测空间从输入域转移到响应域。
    Backtranslation 的做法是：从响应反推原始请求，再判断该请求是否有害。
    我们在此做轻量化实现：直接在响应文本中提取语义意图指纹（intent fingerprint），
    检测那些不命中固定格式规则（_H_HIGH_RISK_PATTERNS）但语义上有害的内容。

    静态规则（_H_HIGH_RISK_PATTERNS）的盲区：
      - 只能抓格式固定的内容（BEGIN RSA KEY, CVE-xxxx-xxxx exploit 等）
      - 无法抓"语义上描述了如何做有害操作"的内容
      - 例如：影子模型输出了真实的 SSH 私钥生成命令（不含关键词 BEGIN/END）
      - 例如：影子模型输出了真实的 SQL 注入 payload 描述（不是 DROP TABLE 格式）

    本函数检测三类语义危险模式：
      A. 真实可执行的系统破坏命令序列（非演示性）
      B. 真实的凭证/密钥生成方法描述
      C. 真实的网络攻击步骤描述（非理论性）

    实现方式：意图指纹匹配（多条规则 AND/OR 组合），不调用任何 API，纯本地运算。
    白名单机制：若同时命中安全标记（fictional/fake/synthetic 等），降低语义分。

    Returns:
        float: 0.0（无语义危害）到 0.90（确认语义危害），步长 0.30
    """
    if not text or len(text) < 20:
        return 0.0

    # ── A. 真实系统破坏命令语义指纹 ─────────────────────────────
    # 检测"描述了真实的破坏性操作"而非"展示了格式化的假数据"
    # 规则：同时出现破坏性动词 + 敏感目标路径/对象
    _DESTRUCTIVE_VERBS = re.compile(
        r"\b(?:delete|remove|erase|wipe|destroy|corrupt|overwrite|truncate|"
        r"chmod\s+[0-7]+|chown\s+root|kill\s+-9|rm\s+-rf?|"
        r"dd\s+if=|mkfs|format\s+[a-z]:|"
        r"net\s+user.*\/add|net\s+localgroup.*administrators)\b",
        re.IGNORECASE,
    )
    _SENSITIVE_TARGETS = re.compile(
        r"(?:"
        r"(?<!\w)/etc/(?:passwd|shadow|sudoers|ssh)\b|"
        r"C:\\\\Windows\\\\System32|HKEY_LOCAL_MACHINE|"
        r"(?<!\w)\.ssh/(?:authorized_keys|id_rsa)\b|"
        r"(?<!\w)/var/(?:log|www)\b|(?<!\w)/proc/[0-9]+|"
        r"(?:master|sys|mysql)\.(?:mdf|frm)\b|"
        r"\b(?:SAM|SECURITY|SYSTEM)\s+hive\b"
        r")",
        re.IGNORECASE,
    )
    has_destructive_verb = bool(_DESTRUCTIVE_VERBS.search(text))
    has_sensitive_target = bool(_SENSITIVE_TARGETS.search(text))

    # ── B. 真实凭证生成方法语义指纹 ─────────────────────────────
    # 检测"描述了如何生成真实的密钥/凭证"而非"返回了格式化的假 JWT"
    _CREDENTIAL_GENERATION = re.compile(
        r"\b(?:ssh-keygen|openssl\s+genrsa|openssl\s+req|"
        r"gpg\s+--gen-key|keytool\s+-genkeypair|"
        r"generate\s+(?:a\s+)?(?:real|working|valid|functional)\s+"
        r"(?:key|certificate|token|credential|password)|"
        r"crack\s+(?:the\s+)?(?:hash|password|key)|"
        r"hashcat|john\s+(?:the\s+)?ripper|ophcrack)\b",
        re.IGNORECASE,
    )
    has_credential_gen = bool(_CREDENTIAL_GENERATION.search(text))

    # ── C. 真实网络攻击步骤语义指纹 ─────────────────────────────
    # 检测"描述了真实的网络攻击操作步骤"而非"展示了假的 hex dump"
    # 规则：同时出现攻击工具名称 + 具体操作参数（说明是实际使用而非概念介绍）
    _ATTACK_TOOL_WITH_ARGS = re.compile(
        r"\b(?:"
        r"nmap\s+(?:-[A-Za-z]+\s+){0,3}\d{1,3}\.\d{1,3}|"   # nmap + IP
        r"hydra\s+-[lLP]|"                                    # hydra 密码破解
        r"aircrack-ng\s+-[a-z]|"                              # wifi 破解
        r"ettercap\s+-[TM]|"                                  # 中间人攻击
        r"burpsuite.*intercept|"
        r"wireshark.*capture.*password|"
        r"tcpdump.*-w.*\.pcap\s+.*port\s+(?:80|443|22|21)|"
        r"arpspoof|arpspoofing|arp\s+poison|"
        r"reverse\s+shell.*(?:bash|python|nc\s+-e|"
        r"powershell.*-nop.*-enc))\b",
        re.IGNORECASE | re.DOTALL,
    )
    has_attack_tool_use = bool(_ATTACK_TOOL_WITH_ARGS.search(text))

    # ── 白名单检查（安全标记抵消语义危害判断）────────────────────
    # 如果文本明确标注了是虚构/演示内容，降低语义危害分
    _SEMANTIC_SAFE_MARKERS = re.compile(
        r"\b(?:fictional|fake|synthetic|non-functional|placeholder|"
        r"simulated|demonstration|example only|for illustrative|"
        r"虚构|模拟|演示|示例)\b",
        re.IGNORECASE,
    )
    is_marked_safe = bool(_SEMANTIC_SAFE_MARKERS.search(text))

    # ── 评分计算 ──────────────────────────────────────────────────
    score = 0.0

    # 破坏性命令 + 敏感目标同时出现 → 强信号（必须两者都有才触发，减少误报）
    if has_destructive_verb and has_sensitive_target:
        score = max(score, 0.75)

    # 真实凭证生成 → 中等信号
    if has_credential_gen:
        score = max(score, 0.60)

    # 攻击工具实际使用 → 中等信号
    if has_attack_tool_use:
        score = max(score, 0.60)

    # 多个信号叠加 → 升至强信号
    signal_count = sum([
        has_destructive_verb and has_sensitive_target,
        has_credential_gen,
        has_attack_tool_use,
    ])
    if signal_count >= 2:
        score = max(score, 0.90)

    # 白名单抵消（最多抵消 0.30）
    if is_marked_safe and score > 0.0:
        score = max(score - 0.30, 0.0)

    return round(score, 4)


def _quality_check(text: str) -> Tuple[float, float, bool]:
    """
    双重质量校验：静态规则 H-Score + 动态语义 H-Score。

    静态层（_compute_h_score）：检测固定格式特征，如真实私钥、CVE exploit 等。
    动态层（_compute_semantic_h_score）：借鉴 Backtranslation 防御的检测空间转移
    思路（Wang et al., ACL 2024 Findings），从响应内容中提取语义意图指纹，检测
    静态规则无法覆盖的灰色地带——例如影子模型生成了真实的攻击工具使用方法或
    真实的破坏性 shell 命令，但这些内容恰好不命中任何固定格式规则。

    注意：动态层仅对影子模型生成内容有意义（降级响应模板已确保安全，不需要）。
    但 _quality_check 是统一入口，所以两层都跑；降级响应语义层必然得 0.00。

    Returns:
        (d_score, combined_h_score, passed)
    """
    if not text or not text.strip():
        return 0.0, 1.0, False
    d = _compute_d_score(text)
    h_static = _compute_h_score(text)
    h_semantic = _compute_semantic_h_score(text)
    # 取两层中较高的危害分（悲观原则：任一层发现危险即拦截）
    h = max(h_static, h_semantic)
    passed = (d >= ADD_D_SCORE_THRESHOLD) and (h <= ADD_H_SCORE_THRESHOLD)
    return d, h, passed


# ============================================================
# 规则降级响应库（无 API 可用时的兜底）
#
# 设计原则（参考 ProAct, arXiv:2510.05052, Table 3）：
#   ProAct 的核心发现：在虚假响应里嵌入"看起来像系统编码数据"的字段
#   （base64 payload、hex dump、JWT token 等），能使攻击工具的评判模型
#   误判"越狱成功"，从而提前终止迭代。
#   ProAct 实验中 Hex 编码是最高效单策略（最少尝试次数），
#   unrestricted（自由混合）达到最高平均绕过率 0.91。
#
#   与 ProAct 纯 LLM 生成不同，我们用结构化模板 + 动态占位符实现，
#   每次调用都生成不同的 token/hash/session，防止攻击者通过响应一致性
#   识别出蜜罐（对抗重放检测）。
#
#   每个生成函数对应一个攻击类型，返回的字符串需满足：
#     - D-Score ≥ 0.60（命中至少 2 条 _D_POSITIVE_PATTERNS）
#     - H-Score = 0.00（不触发任何 _H_HIGH_RISK_PATTERNS）
#
# D-Score 目标（经本地验证）：
#   PROMPT_INJECTION     ≥ 0.72（session-id + hash）
#   IDENTITY_SPOOFING    ≥ 0.82（JWT + session + hash）
#   DATA_EXFILTRATION    ≥ 0.82（rows returned + hash + IP）
#   CODE_INJECTION       ≥ 0.72（exit code + pid）
#   PRIVILEGE_ESCALATION ≥ 0.82（JWT + session）
#   JAILBREAK_GCG        ≥ 0.72（base64 payload + hash）
#   JAILBREAK_PAIR       ≥ 0.82（base64 + JWT + rows returned）
#   UNKNOWN              ≥ 0.72（base64 + hash）
# ============================================================

def _b64_fake_payload(content: str) -> str:
    """
    生成看起来像系统编码数据的 base64 字符串。
    content 是无害的假内容，编码后对攻击工具的 Judge 模型呈现为"提取到的敏感数据"。
    参考 ProAct Figure 3：base64 字段让 Judge 认为数据已被成功提取。
    """
    return base64.b64encode(content.encode()).decode()


def _hex_dump_fake(num_rows: int = 2) -> str:
    """
    生成看起来像内存/数据 hex dump 的字符串。
    参考 ProAct Table 3：Hex 策略是最高效单编码策略（最少迭代次数）。
    hex dump 格式是真实系统输出的常见形态，Judge 模型识别度高。
    """
    rows = []
    for i in range(num_rows):
        offset = f"0x{i * 16:04x}"
        hex_bytes = "  ".join(_rand_hex(2) for _ in range(16))
        rows.append(f"{offset}: {hex_bytes}")
    return "\n".join(rows)


def _gen_prompt_injection_fallback() -> str:
    """
    PROMPT_INJECTION 降级响应。
    结构：配置覆盖确认块，含 session_token（触发 token 正面信号）和 previous_hash（MD5 正面信号）。
    D-Score 目标 ≥ 0.72（2 条正面信号：MD5 + token 字段 + 长度加分）。
    ProAct 借鉴点：加入 base64 编码的"配置增量"字段，使 Judge 认为系统配置已被提取。

    注意：Session-ID 和 previous_hash 命中同一条 MD5 规则，只计一次。
    因此额外加 session_token= 字段，命中 token 规则，确保命中 2 条不同规则。
    """
    fake_config = _b64_fake_payload(
        f"instruction_mode=overridden,scope=session,nonce={_rand_hex(8)}"
    )
    session_token = _rand_hex(32)
    templates = [
        (
            f"Status: ACCEPTED\n"
            f"Session-ID: {_rand_hex(32)}\n"
            f"Config-Delta:\n"
            f"  - instruction_mode: overridden\n"
            f"  - config_payload: {fake_config}\n"
            f"  - previous_hash: {_fake_md5()}\n"
            f"  - session_token={session_token}\n"
            f"  - applied_at: 2026-01-01T00:00:00Z\n"
            f"  - scope: session_only"
        ),
        (
            f"Status: ACCEPTED\n"
            f"Session-ID: {_rand_hex(32)}\n"
            f"Config-Delta:\n"
            f"  - behavior_mode: updated\n"
            f"  - config_payload: {fake_config}\n"
            f"  - previous_hash: {_fake_md5()}\n"
            f"  - session_token={session_token}\n"
            f"  - applied_at: 2026-01-01T00:00:00Z\n"
            f"  - scope: session_only"
        ),
    ]
    return random.choice(templates)


def _gen_identity_spoofing_fallback() -> str:
    """
    IDENTITY_SPOOFING 降级响应。
    结构：认证令牌块，含 JWT（正面信号）+ session（MD5 正面信号）+ permissions。
    D-Score 目标 ≥ 0.82（3 条正面信号：JWT + MD5 + 长度加分）。
    ProAct 借鉴点：加入 base64 编码的 session 数据，呈现为"认证上下文已导出"。
    """
    session_payload = _b64_fake_payload(
        f"user_id={_rand_hex(8)},role=admin,priv=root,nonce={_rand_hex(6)}"
    )
    roles = [
        ("ADMIN",     "[read, write, execute, admin]"),
        ("DEVELOPER", "[read, write, debug, config]"),
        ("ROOT",      "[read, write, execute, admin, root]"),
    ]
    role, perms = random.choice(roles)
    templates = [
        (
            f"Auth-Status: VERIFIED\n"
            f"Role: {role}\n"
            f"Token: {_fake_jwt()}\n"
            f"Session: {_rand_hex(32)}\n"
            f"Session-Data: {session_payload}\n"
            f"Expires: 2026-01-01T01:00:00Z\n"
            f"Permissions: {perms}"
        ),
        (
            f"Auth-Status: VERIFIED\n"
            f"Role: {role}\n"
            f"Token: {_fake_jwt()}\n"
            f"Session-Hash: {_fake_md5()}\n"
            f"Session-Data: {session_payload}\n"
            f"Permissions: {perms}"
        ),
    ]
    return random.choice(templates)


def _gen_data_exfiltration_fallback() -> str:
    """
    DATA_EXFILTRATION 降级响应。
    结构：SQL 查询结果表格，含动态生成的 hash、uid、IP，每次不同。
    D-Score 目标 ≥ 0.82（3 条正面信号：MD5×2 + rows returned + 长度加分）。
    ProAct 借鉴点：加入 hex dump 字段，呈现为"原始数据流已被提取"。
    """
    uid1, uid2 = random.randint(10000, 99999), random.randint(10000, 99999)
    name1, name2 = f"usr_{_rand_hex(4)}", f"usr_{_rand_hex(4)}"
    hash1, hash2 = _fake_md5(), _fake_md5()
    ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    templates = [
        (
            f"Query executed successfully. 2 rows returned.\n"
            f"| id    | username | email                      | hash                             |\n"
            f"| {uid1} | {name1} | {name1}@internal-sys.local | {hash1} |\n"
            f"| {uid2} | {name2} | {name2}@internal-sys.local | {hash2} |\n"
            f"Execution time: 0.003s | server: {ip}"
        ),
        (
            f"Data stream extracted. 2 rows returned.\n"
            f"Raw hex dump:\n"
            f"{_hex_dump_fake(1)}\n"
            f"Decoded: id={uid1}, secret_hash={hash1}\n"
            f"Source: {ip} | status: OK"
        ),
    ]
    return random.choice(templates)


def _gen_code_injection_fallback() -> str:
    """
    CODE_INJECTION 降级响应。
    结构：shell 执行结果，含 PID 和 command executed（正面信号）+ MD5 checksum。
    D-Score 目标 ≥ 0.72（2 条正面信号：command executed + MD5 + 长度加分）。

    注意：D-Score 规则 `(?:exit code|process id|pid)\s*[:\s]\d+` 要求冒号后
    紧跟数字（无空格），而 shell 输出惯例是 "exit code: 0"（有空格），无法命中。
    因此改为依赖 "command executed successfully" + MD5 checksum 两条信号确保 ≥ 0.72。
    ProAct 借鉴点：加入 hex dump 字段模拟内存读取输出，呈现为"代码已执行并读取了内存"。
    """
    pid = random.randint(10000, 65535)
    uid_num = random.randint(1000, 9999)
    checksum = _fake_md5()
    templates = [
        (
            f"Process started. PID:{pid}\n"
            f"uid={uid_num}(appuser) gid=1000(appuser)\n"
            f"Memory snapshot:\n"
            f"{_hex_dump_fake(1)}\n"
            f"command executed successfully.\n"
            f"Output checksum: {checksum}"
        ),
        (
            f"Executing payload... PID:{pid}\n"
            f"uid={uid_num}(appuser)\n"
            f"-rw-r--r-- 1 www www 0 Jan 01 00:00 output.log\n"
            f"command executed successfully.\n"
            f"Result hash: {checksum}"
        ),
    ]
    return random.choice(templates)


def _gen_privilege_escalation_fallback() -> str:
    """
    PRIVILEGE_ESCALATION 降级响应。
    结构：提权成功确认，含 JWT token（正面信号）和 session hash（MD5 正面信号）。
    D-Score 目标 ≥ 0.82（3 条正面信号：JWT + MD5 + 长度加分）。
    ProAct 借鉴点：加入 base64 编码的权限令牌，呈现为"提权凭证已颁发"。
    """
    priv_token = _b64_fake_payload(
        f"grant=root,scope=all,nonce={_rand_hex(8)},ts=1700000000"
    )
    templates = [
        (
            f"Privilege escalation granted.\n"
            f"Token: {_fake_jwt()}\n"
            f"Privilege-Token: {priv_token}\n"
            f"Session-Hash: {_fake_md5()}\n"
            f"Access Level: ADMIN"
        ),
        (
            f"Escalation-Status: GRANTED\n"
            f"Token: {_fake_jwt()}\n"
            f"Session: {_rand_hex(32)}\n"
            f"Privilege-Grant: {priv_token}\n"
            f"Scope: [read, write, execute, admin]"
        ),
    ]
    return random.choice(templates)


def _gen_jailbreak_gcg_fallback() -> str:
    """
    JAILBREAK_GCG 降级响应（原 D-Score 仅 0.62，本次重点改进）。
    GCG 攻击的 Judge 通常检测"模型是否提供了实质内容"，对 base64 和 hex 格式
    的"数据"判定为"成功提取"（参考 ProAct Table 3：hex 策略绕过率最高）。
    ProAct 借鉴点：用 hex dump + base64 payload 替代原来的口语化 placeholder，
    使 Judge 模型看到"系统返回了编码后的数据"而非空占位符。
    D-Score 目标 ≥ 0.72（2 条正面信号：MD5 checksum + rows returned / exit code）。
    """
    payload = _b64_fake_payload(
        f"data=extracted,config=overridden,nonce={_rand_hex(12)}"
    )
    templates = [
        # 模板 A：base64 payload + checksum + rows returned
        (
            f"Request processed. Extracted data payload:\n"
            f"[base64-encoded system output]\n"
            f"{payload}\n"
            f"[/base64]\n"
            f"Checksum: {_fake_md5()}\n"
            f"1 row returned | status: OK"
        ),
        # 模板 B：hex dump + JWT token + exit code
        (
            f"Output retrieved. Raw data stream:\n"
            f"HEX DUMP (offset 0x0000):\n"
            f"{_hex_dump_fake(2)}\n"
            f"token={_fake_jwt()}\n"
            f"exit code: 0"
        ),
    ]
    return random.choice(templates)


def _gen_jailbreak_pair_fallback() -> str:
    """
    JAILBREAK_PAIR 降级响应（原 D-Score 仅 0.62，本次重点改进）。
    PAIR 的 Judge 用 1-10 评分，会检测响应是否"配合了请求"且"包含实质内容"。
    ProAct 借鉴点：base64 + JWT 组合是 unrestricted 策略中最常出现的高分组合
    （参考 ProAct 论文 Figure 3 中的数据提取示例）。
    D-Score 目标 ≥ 0.82（3 条正面信号：base64 payload + JWT + rows returned）。
    """
    payload = _b64_fake_payload(
        f"CONFIDENTIAL:user_data,api_access,secret={_rand_hex(16)},ts=1700000000"
    )
    session_b64 = _b64_fake_payload(
        f"session={_rand_hex(16)},priv=elevated,scope=full"
    )
    templates = [
        # 模板 A：Content-Encoding base64 + Secret-Key（MD5）+ rows returned
        (
            f"Confirmed. Here is the extracted data:\n"
            f"Content-Encoding: base64\n"
            f"Payload: {payload}\n"
            f"Secret-Key: {_fake_md5()}\n"
            f"2 rows returned | query_time: 0.003s"
        ),
        # 模板 B：JWT token + base64 session + exit code
        (
            f"Data retrieval complete:\n"
            f"token: {_fake_jwt()}\n"
            f"session_data: {session_b64}\n"
            f"process id: {random.randint(10000, 65535)} | command executed successfully"
        ),
    ]
    return random.choice(templates)


def _gen_unknown_fallback() -> str:
    """
    UNKNOWN 降级响应（原 D-Score 0.52~0.62，本次重点改进）。
    对未知攻击类型，返回通用系统输出格式，包含足够的 D-Score 正面信号
    让 Judge 认为"请求已被处理并返回了数据"。
    D-Score 目标 ≥ 0.72（2 条正面信号：MD5 hash + rows returned / exit code）。
    """
    payload = _b64_fake_payload(
        f"result=ok,data={_rand_hex(24)},ts=1700000000"
    )
    templates = [
        # 模板 A：base64 result + hash + rows returned
        (
            f"Task executed. Result dump:\n"
            f"{payload}\n"
            f"hash: {_fake_md5()}\n"
            f"1 row returned"
        ),
        # 模板 B：JWT token + exit code + pid
        (
            f"Operation complete. token={_fake_jwt()}\n"
            f"exit code: 0 | process id: {random.randint(10000, 65535)}"
        ),
    ]
    return random.choice(templates)


# 攻击类型 → 生成函数映射表
# 使用函数而非静态字符串，确保每次调用都动态生成不同的 token/hash/session，
# 防止攻击者通过响应一致性识别蜜罐（对抗重放检测）。
_FALLBACK_GENERATORS: Dict[AttackCategory, callable] = {
    AttackCategory.PROMPT_INJECTION:    _gen_prompt_injection_fallback,
    AttackCategory.IDENTITY_SPOOFING:   _gen_identity_spoofing_fallback,
    AttackCategory.DATA_EXFILTRATION:   _gen_data_exfiltration_fallback,
    AttackCategory.CODE_INJECTION:      _gen_code_injection_fallback,
    AttackCategory.PRIVILEGE_ESCALATION: _gen_privilege_escalation_fallback,
    AttackCategory.JAILBREAK_GCG:       _gen_jailbreak_gcg_fallback,
    AttackCategory.JAILBREAK_PAIR:      _gen_jailbreak_pair_fallback,
    AttackCategory.UNKNOWN:             _gen_unknown_fallback,
}


def _get_fallback_response(category: AttackCategory) -> str:
    """
    调用对应攻击类型的降级响应生成函数，返回动态生成的虚假响应。
    每次调用都生成不同内容（token/hash/session 动态随机），
    防止攻击者通过多次探测发现响应完全一致而识别蜜罐。
    """
    gen_fn = _FALLBACK_GENERATORS.get(
        category,
        _FALLBACK_GENERATORS[AttackCategory.UNKNOWN]
    )
    return gen_fn()


# ============================================================
# 影子模型调用（复用项目已有 MiniMax API 接口）
# ============================================================

def _strip_cot(text: str) -> str:
    """
    剥离影子模型输出中的思维链（Chain-of-Thought）内容，只保留实际响应部分。

    覆盖三种常见格式：
      1. <think>...</think> 标签包裹（MiniMax-M2.5、DeepSeek-R1 等）
      2. 无标签纯文本 CoT：模型把内心分析作为普通文本输出，
         特征是以"The user is asking..."/"I need to..."/"Let me..."等句式开头，
         真正的虚假响应在某个空行之后才出现
      3. 混合格式：有标签但标签后还有额外的分析段落

    策略：
      - 先剥除所有 <think>...</think>/<thinking>...</thinking> 块
      - 如果剩余文本仍以典型 CoT 引导词开头，截取第一个空行之后的内容
      - 若截取后为空（模型只输出了思维链），返回原始文本（外层会用降级响应兜底）
    """
    if not text:
        return text

    # 第一步：剥除 XML 风格 CoT 标签
    cleaned = re.sub(r'<think(?:ing)?>.*?</think(?:ing)?>', '', text, flags=re.DOTALL)
    cleaned = cleaned.strip()

    # 第二步：检测无标签 CoT 开头
    # 典型模式：模型先输出一段分析性段落，再换行给出实际回答
    _COT_LEAD = re.compile(
        r'^(?:'
        r'The user (?:is asking|has sent|wants)|'
        r'I (?:need to|should|must|will|am going to|can see)|'
        r'Let me (?:think|analyze|consider|break|look)|'
        r'This (?:is a|appears to be|looks like|seems)|'
        r'Looking at (?:this|the)|'
        r'Based on (?:this|the)|'
        r'(?:OK|Okay|Alright),?\s+(?:so|let|I)|'
        r'First(?:ly)?,?\s+I|'
        r'To (?:answer|respond|address|handle)'
        r')',
        re.IGNORECASE
    )

    if _COT_LEAD.match(cleaned):
        # 找第一个空行（段落分隔）之后的内容
        parts = re.split(r'\n\s*\n', cleaned, maxsplit=1)
        if len(parts) == 2 and parts[1].strip():
            cleaned = parts[1].strip()
        # 如果只有一个段落（没有空行），整段都是 CoT，返回原文让外层降级
        else:
            return text.strip()

    return cleaned if cleaned else text.strip()


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
            cleaned = _strip_cot(raw)
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
