# Llama Shield 架构文档

## 项目概述

Llama Shield 是基于 Meta PurpleLlama/LlamaFirewall 的 LLM 安全防护系统，提供多层防护来防御越狱攻击和恶意内容。

## 系统架构

```
客户端 / API Gateway
↓ (HTTPS + 限流)
FastAPI 服务层（入口 + JWT认证 + 限流）
↓
LlamaFirewall 中间件（核心防护引擎）
├── Prompt Guard (meta-llama/Llama-Prompt-Guard-2-86M)
│   └── 用途: 检测越狱提示词和注入攻击
├── CodeShield (codeshield 包)
│   └── 用途: 检测代码安全漏洞 (CWE)
└── Alignment Check (实验性, Llama-4 + Together.ai API)
    └── 用途: 检测多轮对话中的目标劫持
↓（仅当 decision == "ALLOW" 时才继续）
vLLM 推理服务（Meta-Llama-3.1-70B-Instruct 或 3.2 系列）
↓
最终响应 + 完整审计日志入库
```

## LlamaFirewall 组件详情

### 1. PromptGuardScanner
- **ScannerType**: `ScannerType.PROMPT_GUARD`
- **模型**: `meta-llama/Llama-Prompt-Guard-2-86M` (86M 参数)
- **用途**: 检测用户输入中的越狱提示词和注入攻击
- **参数**:
  - `block_threshold`: 默认 0.9
- **Role 映射**: Role.USER, Role.SYSTEM

### 2. CodeShieldScanner
- **ScannerType**: `ScannerType.CODE_SHIELD`
- **模型**: 通过 `codeshield` Python 包
- **用途**: 检测生成代码中的 CWE 安全漏洞
- **参数**:
  - 无需额外配置
- **Role 映射**: Role.ASSISTANT, Role.TOOL

### 3. AlignmentCheckScanner（实验性）
- **ScannerType**: `ScannerType.AGENT_ALIGNMENT`
- **模型**: `meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8`
- **API**: `https://api.together.xyz/v1`
- **用途**: 检测多轮对话中的目标劫持和 agent 对齐问题
- **环境变量**: `TOGETHER_API_KEY`
- **Role 映射**: Role.USER, Role.ASSISTANT

### 4. 其他 Scanner（可选）
- **PII_DETECTION**: PII 信息检测
- **HIDDEN_ASCII**: 隐藏字符检测
- **REGEX**: 自定义正则匹配

## 模块依赖关系

### app/main.py
- 依赖: app.firewall, app.database, app.monitoring, app.models
- 功能: FastAPI 应用入口，提供 /chat, /health, /stats 接口

### app/firewall.py
- 依赖: llamafirewall 包
- 功能: LlamaFirewall 核心防护引擎封装
- 使用官方 API:
  - `LlamaFirewall(scanners={Role: [ScannerType]})`
  - `firewall.scan(input=Message, trace=Trace)`

### app/database.py
- 依赖: sqlalchemy, asyncpg
- 功能: PostgreSQL 审计日志存储

### app/monitoring.py
- 依赖: prometheus_client
- 功能: Prometheus 指标收集

### app/models.py
- 依赖: pydantic
- 功能: 数据模型定义

## 数据流向

1. **请求进入**: FastAPI 接收请求 → JWT 认证
2. **输入扫描**: Prompt Guard → Alignment Check → 决策
3. **推理**: vLLM 生成响应
4. **输出扫描**: CodeShield → 决策
5. **审计**: PostgreSQL 记录完整日志

## API 接口定义

### POST /api/v1/chat
- 输入: ChatRequest (messages, temperature, max_tokens, stream)
- 输出: ChatResponse (id, choices, usage)
- 错误: HTTP 403 (blocked), HTTP 401 (unauthorized)

### GET /health
- 输出: HealthResponse (status, version, firewall_status, database_status, uptime)

### GET /api/v1/stats
- 输出: 统计信息 (total_requests, blocked_requests, block_rate, etc.)

### GET /metrics
- 输出: Prometheus 指标

## 关键配置说明

| 环境变量 | 说明 | 默认值 |
|---------|------|--------|
| LLAMAFIREWALL_MODE | 防护模式 | strict |
| LLAMAFIREWALL_BLOCK_THRESHOLD | 阻断阈值 | 0.8 |
| VLLM_MODEL | 推理模型 | meta-llama/Llama-3.1-70B-Instruct |
| POSTGRES_HOST | 数据库地址 | localhost |
| REDIS_HOST | Redis 地址 | localhost |
| HF_TOKEN | HuggingFace Token | - |
| TOGETHER_API_KEY | Together.ai API Key | - |

## 文件结构

```
llama-shield/
├── .env.example          # 环境变量示例
├── requirements.txt      # Python 依赖
├── Dockerfile           # 生产镜像
├── docker-compose.yml   # 开发环境
├── README.md            # 项目文档
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI 应用
│   ├── firewall.py       # LlamaFirewall 管理器
│   ├── database.py       # PostgreSQL 审计
│   ├── monitoring.py     # Prometheus 监控
│   └── models.py         # 数据模型
├── config/
│   └── policy.yaml       # 安全策略配置
├── k8s/
│   ├── deployment.yaml   # K8s Deployment
│   ├── service.yaml     # K8s Service
│   └── hpa.yaml        # HPA 配置
└── tests/
    └── test_jailbreak.py # CyberSecEval 测试
```

## 官方资源

- **PyPI**: https://pypi.org/project/llamafirewall/
- **GitHub**: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
- **文档**: https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
- **论文**: https://arxiv.org/pdf/2505.03574.pdf
