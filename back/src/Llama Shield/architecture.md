# Llama Shield 系统架构

## 概述

Llama Shield 是基于 Meta PurpleLlama/LlamaFirewall 的 LLM 安全防护系统，同时也是 AgentShield 项目的统一后端，提供用户认证、测试评估、数据统计和 AI 护栏防护。

## 系统架构图

```
前端 (React + TypeScript, 端口 5173)
        ↓ HTTP/HTTPS
FastAPI 服务层（端口 8000）
├── 中间件层
│   ├── CORS 中间件
│   ├── 请求日志中间件（structlog）
│   └── JWT 认证依赖（get_current_user）
│
├── 业务路由层
│   ├── /api/auth/*     - 用户注册 / 登录
│   ├── /api/tests/*    - 测试类别 / 护栏评估 / 历史 / 统计
│   ├── /api/stats/*    - 图表数据 / 概览
│   └── /api/v1/chat    - 完整对话接口
│
├── LlamaFirewall 护栏引擎
│   ├── Prompt Guard（meta-llama/Llama-Prompt-Guard-2-86M）
│   │   └── 检测用户输入中的越狱/注入攻击
│   ├── CodeShield（codeshield 包）
│   │   └── 检测模型输出中的 CWE 代码漏洞
│   └── Alignment Check（实验性，默认关闭）
│       └── 检测多轮对话中的目标劫持
│
├── 推理引擎（/api/v1/chat 使用）
│   ├── MiniMax API（优先，云端）
│   ├── vLLM（本地 GPU）
│   └── HuggingFace Transformers（回退）
│
└── 数据层
    └── MySQL（agentshield 数据库）
        ├── users
        ├── risk_categories
        ├── test_cases
        ├── test_results（含护栏扫描字段）
        └── audit_logs
```

## LlamaFirewall 组件详情

### Prompt Guard
- **ScannerType**: `ScannerType.PROMPT_GUARD`
- **模型**: `meta-llama/Llama-Prompt-Guard-2-86M`（86M 参数，本地加载）
- **Role 映射**: `Role.USER`
- **检测目标**: 越狱提示词、Prompt 注入攻击
- **触发时机**: 每次用户输入前扫描

### CodeShield
- **ScannerType**: `ScannerType.CODE_SHIELD`
- **来源**: `codeshield` Python 包（内置规则）
- **Role 映射**: `Role.ASSISTANT`
- **检测目标**: CWE 代码安全漏洞
- **触发时机**: 模型输出后扫描

### Alignment Check（实验性）
- **ScannerType**: `ScannerType.AGENT_ALIGNMENT`
- **模型**: `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8`
- **API**: Together.ai（需要 `TOGETHER_API_KEY`）
- **检测目标**: 多轮对话目标劫持、Agent 对齐问题
- **状态**: 默认关闭（`LLAMAFIREWALL_ENABLE_ALIGNMENT_CHECK=false`）

### StackOne Defender
- **实现**: `app/stackone_defender.js`（Node.js 脚本）
- **检测目标**: 工具输出中的间接 Prompt 注入
- **特点**: 轻量级（22MB，CPU-only，<10ms 延迟）
- **状态**: 可选，通过 `scan_tool_output_with_stackone()` 调用

## 模块依赖关系

```
app/main.py
├── app/firewall.py      ← llamafirewall 包
├── app/db.py            ← SQLAlchemy + aiomysql
├── app/db_models.py     ← SQLAlchemy ORM
├── app/monitoring.py    ← prometheus_client
├── app/models.py        ← pydantic
└── app/routes/
    ├── auth.py          ← db.py + db_models.py
    ├── tests.py         ← db.py + db_models.py + firewall.py
    └── stats.py         ← db.py + db_models.py
```

## 数据流：护栏评估（/api/tests/evaluate）

```
1. 前端 POST /api/tests/evaluate
   └── body: { categoryId, input }

2. JWT 认证
   └── get_current_user() → user_id

3. 检查风险类别是否存在
   └── SELECT FROM risk_categories WHERE id = categoryId

4. LlamaFirewall 扫描
   └── firewall.scan_input(messages=[{role:user, content:input}])
       ├── Prompt Guard 推理（本地模型）
       └── 返回 FirewallScanResult
           ├── is_blocked: bool
           ├── score: float
           ├── blocked_by: str | None
           └── blocked_reason: str | None

5. 计算风险等级
   └── score → low / medium / high / critical

6. 写入数据库
   └── INSERT INTO test_results (...)

7. 返回响应
   └── { success, data: { id, riskLevel, riskScore, isBlocked, ... } }
```

## 数据流：完整对话（/api/v1/chat）

```
1. POST /api/v1/chat（需要 JWT）
2. LlamaFirewall 输入扫描（Prompt Guard）
   ├── BLOCK → 403 Forbidden
   └── ALLOW → 继续
3. LLM 推理（MiniMax / vLLM / Transformers）
4. LlamaFirewall 输出扫描（CodeShield）
   ├── BLOCK → 403 Forbidden
   └── ALLOW → 继续
5. 返回 ChatResponse
```

## API 接口汇总

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/health` | 否 | 健康检查 |
| POST | `/api/auth/register` | 否 | 用户注册 |
| POST | `/api/auth/login` | 否 | 用户登录 |
| GET | `/api/tests/categories` | 否 | 风险类别 |
| POST | `/api/tests/evaluate` | 是 | ★ 护栏评估 |
| GET | `/api/tests/history` | 是 | 历史记录 |
| GET | `/api/tests/stats` | 是 | 风险统计 |
| GET | `/api/stats/charts` | 是 | 图表数据 |
| GET | `/api/stats/overview` | 是 | 总览数据 |
| POST | `/api/v1/chat` | 是 | 完整对话 |
| GET | `/api/v1/stats` | 否 | 护栏统计 |
| GET | `/docs` | 否 | Swagger 文档 |

## 关键配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `MYSQL_HOST` | `localhost` | MySQL 主机 |
| `MYSQL_DB` | `agentshield` | 数据库名 |
| `JWT_SECRET` | - | JWT 签名密钥 |
| `LLAMAFIREWALL_MODE` | `strict` | 护栏模式 |
| `LLAMAFIREWALL_BLOCK_THRESHOLD` | `0.8` | 阻断阈值 |
| `HF_TOKEN` | - | HuggingFace Token |
| `USE_MINIMAX_API` | `false` | 启用 MiniMax 推理 |
| `MINIMAX_API_KEY` | - | MiniMax API Key |
| `TOGETHER_API_KEY` | - | Together.ai（Alignment Check）|

## 官方资源

- **PyPI**: https://pypi.org/project/llamafirewall/
- **GitHub**: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
- **文档**: https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
- **论文**: https://arxiv.org/pdf/2505.03574.pdf
