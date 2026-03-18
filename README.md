# AgentShield - AI 安全护栏系统

基于 Meta PurpleLlama/LlamaFirewall 的完整 AI 安全护栏解决方案，防护越狱攻击、Prompt 注入、代码安全漏洞等威胁。

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         用户浏览器                                  │
│                      访问 http://localhost:5173                      │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    前端 (React + Vite)                               │
│                      localhost:5173                                  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ /api
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Express 后端 (唯一 API 网关)                            │
│                      localhost:3001                                  │
│                                                                      │
│   • 用户认证 (JWT + bcrypt)                                         │
│   • 测试管理 (评估 / 历史 / 统计)                                    │
│   • 调用 Llama Shield 进行 AI 检测                                  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ HTTP
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Llama Shield (AI 检测服务)                              │
│                      localhost:8000                                  │
│                                                                      │
│   • Prompt Guard - 越狱/注入检测                                     │
│   • CodeShield - 代码安全检测                                        │
│   • Alignment Check - 目标劫持检测 (MiniMax API)                     │
│   • MiniMax API - 对话推理                                          │
└─────────────────────────────────────────────────────────────────────┘
```

## 快速开始

### 1. 启动 Llama Shield (AI 检测服务)

```bash
cd back/src/Llama Shield

# 安装依赖
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 启动服务
python -m app.main
```

### 2. 启动 Express 后端 (API 网关)

```bash
cd back
npm install
npm run dev
```

### 3. 启动前端

```bash
cd front
npm install
npm run dev
```

访问 `http://localhost:5173`

---

## 项目结构

```
agentshield/
├── front/                          # 前端 (React + TypeScript)
│   ├── src/
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   ├── components/
│   │   │   └── Navbar.tsx
│   │   ├── pages/
│   │   │   ├── LandingPage.tsx
│   │   │   ├── LoginPage.tsx
│   │   │   ├── BringYourOwnPage.tsx
│   │   │   └── TryExamplePage.tsx
│   │   ├── services/
│   │   │   └── api.ts
│   │   └── store/
│   │       └── authStore.ts
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
│
├── back/                           # Express 后端 (唯一 API 网关)
│   ├── src/
│   │   ├── index.ts               # 入口
│   │   ├── routes/
│   │   │   ├── auth.ts            # 认证
│   │   │   ├── tests.ts           # 测试评估
│   │   │   └── stats.ts           # 统计
│   │   ├── middleware/
│   │   │   └── auth.ts            # JWT 中间件
│   │   ├── validators/
│   │   │   └── schemas.ts         # 验证规则
│   │   └── services/
│   │       └── llamaShield.ts      # AI 检测服务客户端
│   ├── prisma/
│   │   └── schema.prisma          # 数据库模型
│   ├── package.json
│   └── .env
│
└── back/src/Llama Shield/          # Python AI 护栏服务
    ├── app/
    │   ├── main.py                 # FastAPI 入口
    │   ├── firewall.py             # 核心防护逻辑
    │   ├── db.py                  # MySQL 连接
    │   ├── db_models.py           # 数据模型
    │   ├── models.py              # Pydantic 模型
    │   └── monitoring.py          # 监控
    ├── config/
    │   └── policy.yaml            # 策略配置
    ├── .env                       # 环境变量
    ├── requirements.txt           # Python 依赖
    ├── docker-compose.yml         # Docker 配置
    └── README.md
```

---

## 技术栈

### 前端
- React 18 + TypeScript
- Tailwind CSS + Framer Motion
- Zustand + Axios + React Router
- ECharts 数据可视化

### 后端
- **Express** (端口 3001) - 唯一 API 网关
  - TypeScript
  - Prisma ORM
  - JWT + bcrypt

- **Llama Shield** (端口 8000) - AI 检测服务
  - Python 3.10+
  - FastAPI + Uvicorn
  - LlamaFirewall 1.0.3 (Meta PurpleLlama)
  - MiniMax API (对话推理)

### 数据库
- MySQL 8.0+
- 数据库名：`agentshield`

---

## API 端点

### 认证
```
POST /api/auth/register    # 用户注册
POST /api/auth/login       # 用户登录
```

### 测试与护栏评估
```
GET  /api/tests/categories  # 获取风险类别
POST /api/tests/evaluate     # AI 护栏评估
GET  /api/tests/history      # 获取测试历史
GET  /api/tests/stats       # 按风险等级统计
```

### 统计与图表
```
GET /api/stats/charts       # 风险分布 + 分类图表
GET /api/stats/overview     # 总量 / 危险数 / 平均分
```

### Llama Shield 原始接口
```
POST /api/v1/chat          # 完整对话（含输入/输出扫描）
GET  /health               # 健康检查
```

---

## 数据库表

| 表名 | 说明 |
|------|------|
| `users` | 用户信息 |
| `risk_categories` | 风险类别 |
| `test_cases` | 预设测试用例 |
| `test_results` | 测试结果 |

---

## 环境配置

### Express 后端 (.env)
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

# MiniMax API (推理)
USE_MINIMAX_API=true
MINIMAX_API_KEY=your-api-key
MINIMAX_MODEL=MiniMax-M2.5
```

---

## LlamaFirewall 防护层

| Scanner | 检测目标 | 触发条件 |
|---------|---------|----------|
| **Prompt Guard** | 越狱提示词、Prompt 注入攻击 | 用户输入扫描 |
| **CodeShield** | CWE 代码安全漏洞 | 模型输出扫描 |
| **Alignment Check** | 多轮目标劫持 | 默认开启 (MiniMax API) |

---

## 常用命令

```bash
# 启动 Llama Shield
cd back/src/Llama Shield
python -m app.main

# 启动 Express 后端
cd back
npm run dev

# 启动前端
cd front
npm run dev

# 初始化数据库
cd back
npm run prisma:migrate
npm run prisma:seed
```

---

## 参考资源

- [LlamaFirewall PyPI](https://pypi.org/project/llamafirewall/)
- [PurpleLlama GitHub](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [MiniMax API](https://platform.minimaxi.com/)

---

## 许可证

MIT
