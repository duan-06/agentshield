# AgentShield 后端

本项目包含两个后端服务：
1. **Express** (端口 3001) - 唯一 API 网关
2. **Llama Shield** (端口 8000) - AI 检测服务

## 服务说明

### Express 后端 (API 网关)
处理用户认证、测试管理、统计等功能，并调用 Llama Shield 进行 AI 安全检测。

### Llama Shield (AI 检测服务)
基于 Meta PurpleLlama/LlamaFirewall 的 AI 安全护栏，提供越狱检测、代码安全检测等功能。

## 快速启动

### 1. 启动 Llama Shield

```bash
cd src/Llama Shield
python -m app.main
```

### 2. 启动 Express 后端

```bash
cd back
npm install
npm run dev
```

## 目录结构

```
back/
├── src/
│   ├── index.ts                 # Express 入口
│   ├── routes/
│   │   ├── auth.ts            # 认证路由
│   │   ├── tests.ts           # 测试评估路由
│   │   └── stats.ts           # 统计路由
│   ├── middleware/
│   │   └── auth.ts            # JWT 中间件
│   ├── validators/
│   │   └── schemas.ts         # 验证规则
│   └── services/
│       └── llamaShield.ts      # Llama Shield 客户端
│
├── src/Llama Shield/           # AI 检测服务
│   ├── app/
│   │   ├── main.py            # FastAPI 入口
│   │   ├── firewall.py        # 核心防护逻辑
│   │   ├── db.py             # MySQL 连接
│   │   ├── db_models.py      # 数据模型
│   │   └── monitoring.py      # 监控
│   ├── config/
│   │   └── policy.yaml
│   ├── .env
│   └── requirements.txt
│
└── prisma/
    ├── schema.prisma          # 数据库模型
    └── seed.ts                # 初始化数据
```

## 技术栈

### Express 后端
- TypeScript
- Express
- Prisma ORM
- JWT + bcrypt

### Llama Shield
- Python 3.10+
- FastAPI + Uvicorn
- LlamaFirewall 1.0.3
- SQLAlchemy + aiomysql
- MiniMax API

## API 端点

### 认证 `/api/auth`
| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/register` | 用户注册 |
| POST | `/login` | 用户登录 |

### 测试 `/api/tests`
| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/categories` | 获取风险类别 | 否 |
| POST | `/evaluate` | AI 护栏评估 | 是 |
| GET | `/history` | 测试历史 | 是 |
| GET | `/stats` | 风险统计 | 是 |

### 统计 `/api/stats`
| 方法 | 路径 | 说明 | 认证 |
|------|------|------|------|
| GET | `/charts` | 图表数据 | 是 |
| GET | `/overview` | 总览统计 | 是 |

## 环境变量

### Express (.env)
```env
DATABASE_URL="mysql://root:@localhost:3306/agentshield"
JWT_SECRET="o3AICVQ3pWXqTBV3ocQQdVOSaopLXyxs"
PORT=3001
LLAMA_SHIELD_URL="http://localhost:8000"
```

### Llama Shield (.env)
```env
# MySQL
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=agentshield
MYSQL_USER=root
MYSQL_PASSWORD=

# JWT
JWT_SECRET=o3AICVQ3pWXqTBV3ocQQdVOSaopLXyxs

# LlamaFirewall
LLAMAFIREWALL_MODE=strict
LLAMAFIREWALL_ENABLE_INPUT_SCAN=true
LLAMAFIREWALL_ENABLE_OUTPUT_SCAN=true
LLAMAFIREWALL_ENABLE_ALIGNMENT_CHECK=true

# MiniMax API
USE_MINIMAX_API=true
MINIMAX_API_KEY=sk-api-vMw6htg6gyHg9K5dSLobWQU_zJIz29BosP0vuGSBuG4apcY-YQToS9-j86uaUgJIm_0iaplCemHBN7KvPGn4xfzx-duxtIwaa1npfel-wS0eO1dLHcBup6Y
```

## 数据库初始化

```bash
cd back
npm run prisma:migrate
npm run prisma:seed
```

## LlamaFirewall 防护层

| Scanner | 检测目标 |
|---------|---------|
| Prompt Guard | 越狱提示词、注入攻击 |
| CodeShield | CWE 代码安全漏洞 |
| Alignment Check | 目标劫持检测 |
