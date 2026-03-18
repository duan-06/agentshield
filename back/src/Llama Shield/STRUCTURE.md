# Llama Shield - 项目结构说明

## 目录结构

```
Llama Shield/
├── app/                        # 核心应用代码
│   ├── __init__.py
│   ├── main.py                 # FastAPI 入口，注册路由、生命周期管理
│   ├── firewall.py             # LlamaFirewall 护栏引擎封装
│   ├── db.py                   # MySQL 异步数据库连接（aiomysql）
│   ├── db_models.py            # SQLAlchemy ORM 模型
│   │                           #   User / RiskCategory / TestCase
│   │                           #   TestResult / AuditLog
│   ├── database.py             # 原 PostgreSQL 审计日志模块（已弃用）
│   ├── monitoring.py           # Prometheus 指标采集
│   ├── models.py               # Pydantic 请求/响应模型
│   ├── stackone_defender.js    # StackOne Defender（工具输出间接注入检测）
│   └── routes/                 # 业务路由模块
│       ├── __init__.py
│       ├── auth.py             # 用户注册 / 登录 / JWT 认证依赖
│       ├── tests.py            # 护栏评估 / 历史记录 / 统计
│       └── stats.py            # 图表数据 / 概览统计
│
├── config/
│   └── policy.yaml             # 护栏策略配置文件
│
├── k8s/                        # Kubernetes 部署配置
│   ├── deployment.yaml
│   ├── service.yaml
│   └── hpa.yaml
│
├── tests/
│   ├── __init__.py
│   └── test_jailbreak.py       # 越狱攻击基准测试（ASR / FPR）
│
├── .env                        # 本地环境变量（不提交 Git）
├── .env.example                # 环境变量模板
├── requirements.txt            # Python 依赖列表
├── Dockerfile                  # 容器镜像构建
├── docker-compose.yml          # 本地多服务编排
├── README.md                   # 功能说明与快速开始
├── STRUCTURE.md                # 本文件
├── architecture.md             # 系统架构设计
├── module_logs.md              # 模块开发日志
├── logs.md                     # 运行日志记录
└── difficulties.md             # 开发难点与解决方案
```

## 核心模块说明

### `app/main.py` - 应用入口
- 加载 `.env` 环境变量
- 注册 CORS 中间件
- 注册业务路由（auth / tests / stats）
- `lifespan` 管理 MySQL 初始化、LlamaFirewall 初始化、资源清理
- 原有 `/api/v1/chat` 聊天接口（支持 vLLM / transformers / MiniMax API）

### `app/firewall.py` - 护栏引擎
- `LlamaFirewallManager`：封装 LlamaFirewall 初始化和扫描
- `scan_input()`：扫描用户输入（Prompt Guard）
- `scan_output()`：扫描模型输出（CodeShield）
- `scan_tool_output_with_stackone()`：工具输出间接注入检测
- `alignment_check_with_qwen()`：目标劫持检测（实验性）

### `app/db.py` - 数据库连接
- 基于 `aiomysql` + `SQLAlchemy 2.x` 异步引擎
- `init_db()`：初始化连接池，自动 `CREATE TABLE IF NOT EXISTS`
- `get_session()`：FastAPI 依赖注入，提供异步 Session
- `close_db()`：关闭连接池

### `app/db_models.py` - 数据模型

| 模型 | 表名 | 说明 |
|------|------|------|
| `User` | `users` | 用户账号 |
| `RiskCategory` | `risk_categories` | 风险类别 |
| `TestCase` | `test_cases` | 预设测试用例 |
| `TestResult` | `test_results` | 测试结果（含护栏扫描字段）|
| `AuditLog` | `audit_logs` | 审计日志 |

### `app/routes/auth.py` - 认证路由
- `POST /api/auth/register`：注册用户，返回 JWT
- `POST /api/auth/login`：验证密码，返回 JWT
- `get_current_user()`：JWT 验证依赖，返回 `user_id: int`

### `app/routes/tests.py` - 测试评估路由
- `GET /api/tests/categories`：返回所有风险类别及测试用例
- `POST /api/tests/evaluate`：调用 LlamaFirewall 扫描，结果写入 `test_results`
- `GET /api/tests/history`：当前用户历史记录
- `GET /api/tests/stats`：按风险等级分组统计

### `app/routes/stats.py` - 统计路由
- `GET /api/stats/charts`：风险等级分布 + 分类测试数量
- `GET /api/stats/overview`：总测试数 / 危险数 / 平均分 / 阻断数

## 数据流：护栏评估

```
前端 POST /api/tests/evaluate
    ↓
JWT 认证 (get_current_user)
    ↓
检查 RiskCategory 是否存在
    ↓
LlamaFirewall.scan_input(messages)
    ├── Prompt Guard 扫描
    └── 返回 FirewallScanResult
    ↓
计算风险等级 (score → low/medium/high/critical)
    ↓
写入 test_results 表
    ↓
返回评估结果 JSON
```

## 环境变量索引

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MYSQL_HOST` | `localhost` | MySQL 主机 |
| `MYSQL_PORT` | `3306` | MySQL 端口 |
| `MYSQL_DB` | `agentshield` | 数据库名 |
| `MYSQL_USER` | `root` | 用户名 |
| `MYSQL_PASSWORD` | `123456` | 密码 |
| `JWT_SECRET` | - | JWT 签名密钥 |
| `LLAMAFIREWALL_MODE` | `strict` | 护栏模式 |
| `LLAMAFIREWALL_BLOCK_THRESHOLD` | `0.8` | 阻断阈值 |
| `HF_TOKEN` | - | HuggingFace Token |
| `USE_MINIMAX_API` | `false` | 启用 MiniMax 推理 |
| `MINIMAX_API_KEY` | - | MiniMax API Key |
