# AgentShield 后端

基于 **Python FastAPI + LlamaFirewall** 的统一后端服务，提供用户认证、AI 安全护栏评估、测试管理和统计分析。

> 原 Express/TypeScript 后端已迁移至 Python FastAPI，两者共用同一 MySQL 数据库。

## 服务入口

```
后端服务：http://localhost:8000
API 文档：http://localhost:8000/docs
```

## 快速启动

```bash
cd "src/Llama Shield"

# 安装依赖
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 配置环境
cp .env.example .env
# 编辑 .env，至少填写 MYSQL_PASSWORD 和 JWT_SECRET

# 启动
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 目录结构

```
back/
├── prisma/                    # 数据库 Schema（参考用）
│   ├── schema.prisma          # MySQL 表结构定义
│   └── seed.ts                # 初始化示例数据
│
└── src/
    └── Llama Shield/          # ★ 主后端服务
        ├── app/
        │   ├── main.py        # FastAPI 应用入口
        │   ├── firewall.py    # LlamaFirewall 护栏引擎
        │   ├── db.py          # MySQL 异步数据库连接
        │   ├── db_models.py   # SQLAlchemy ORM 模型
        │   ├── monitoring.py  # Prometheus 指标
        │   ├── models.py      # Pydantic 数据模型
        │   └── routes/
        │       ├── __init__.py
        │       ├── auth.py    # 认证路由
        │       ├── tests.py   # 测试评估路由
        │       └── stats.py   # 统计路由
        ├── config/
        │   └── policy.yaml
        ├── tests/
        │   └── test_jailbreak.py
        ├── .env               # 本地配置（不提交 Git）
        ├── .env.example       # 配置模板
        ├── requirements.txt
        └── Dockerfile
```

## 技术栈

| 组件 | 技术 |
|------|------|
| Web 框架 | FastAPI + Uvicorn |
| AI 护栏 | LlamaFirewall 1.0.3 |
| 数据库 | MySQL 8 + SQLAlchemy 2 + aiomysql |
| 认证 | JWT（python-jose）+ bcrypt（passlib）|
| 日志 | structlog |
| 监控 | Prometheus |

## API 端点

### 认证 `/api/auth`
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/register` | 用户注册（返回 JWT）|
| POST | `/login` | 用户登录（返回 JWT）|

### 测试 `/api/tests`
| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/categories` | 获取风险类别 | 否 |
| POST | `/evaluate` | ★ AI 护栏评估 | 是 |
| GET | `/history` | 测试历史记录 | 是 |
| GET | `/stats` | 按风险等级统计 | 是 |

### 统计 `/api/stats`
| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/charts` | 图表数据 | 是 |
| GET | `/overview` | 总览统计 | 是 |

### 其他
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| POST | `/api/v1/chat` | 完整对话接口（含护栏）|
| GET | `/api/v1/stats` | 护栏运行统计 |

## 环境变量说明

```env
# MySQL 数据库
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=agentshield
MYSQL_USER=root
MYSQL_PASSWORD=123456

# JWT 密钥
JWT_SECRET=your-secret-key-change-in-production

# LlamaFirewall 配置
LLAMAFIREWALL_MODE=strict          # strict / balanced / permissive
LLAMAFIREWALL_BLOCK_THRESHOLD=0.8
LLAMAFIREWALL_ENABLE_INPUT_SCAN=true
LLAMAFIREWALL_ENABLE_CODE_SCAN=true

# 推理引擎（可选）
USE_MINIMAX_API=false
MINIMAX_API_KEY=

# HuggingFace Token（Prompt Guard 模型）
HF_TOKEN=
HF_HUB_OFFLINE=1
```

## 数据库表说明

| 表名 | 说明 |
|------|------|
| `users` | 用户账号（username / email / password_hash）|
| `risk_categories` | 风险类别定义 |
| `test_cases` | 预设测试用例 |
| `test_results` | 测试结果（含护栏扫描分数、风险等级）|
| `audit_logs` | LlamaFirewall 审计日志 |

初始化示例数据：
```bash
cd back
npm run prisma:seed
```

## 初始化示例数据

```bash
# 方式1：使用 Prisma seed（推荐）
cd back
npm install
npm run prisma:seed

# 方式2：手动 SQL（MySQL Workbench 或命令行）
mysql -u root -p agentshield < prisma/seed.sql
```
