# AgentShield - AI 安全护栏系统

基于 Meta PurpleLlama/LlamaFirewall 的完整 AI 安全护栏解决方案，防护越狱攻击、Prompt 注入、代码安全漏洞等威胁。

## 系统架构

```
前端 (React + TypeScript)
        ↓ HTTP
FastAPI 后端（统一入口，端口 8000）
├── 用户认证（JWT + bcrypt）
├── 测试管理（评估 / 历史 / 统计）
├── LlamaFirewall 护栏引擎
│   ├── Prompt Guard（越狱/注入检测）
│   └── CodeShield（代码漏洞检测）
└── MySQL 数据库（agentshield）
```

## 快速开始

### 1. 启动后端（Python FastAPI）

```bash
cd back/src/Llama Shield

# 安装依赖
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env，填写 MySQL 连接信息和 JWT_SECRET

# 启动服务
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. 启动前端（React）

```bash
cd front
npm install
npm run dev
```

访问 `http://localhost:5173`

## 项目结构

```
agentshield/
├── front/                          # React 前端应用
│   ├── src/
│   │   ├── pages/                 # 页面组件
│   │   ├── services/              # API 服务
│   │   ├── store/                 # Zustand 状态管理
│   │   └── App.tsx
│   └── package.json
│
├── back/                          # 后端目录
│   ├── prisma/                    # Prisma Schema（MySQL 表结构参考）
│   │   ├── schema.prisma
│   │   └── seed.ts                # 初始化数据脚本
│   └── src/
│       └── Llama Shield/          # ★ 统一后端（FastAPI + LlamaFirewall）
│           ├── app/
│           │   ├── main.py        # FastAPI 主入口，注册所有路由
│           │   ├── firewall.py    # LlamaFirewall 护栏引擎
│           │   ├── db.py          # MySQL 异步连接（aiomysql）
│           │   ├── db_models.py   # SQLAlchemy 数据模型
│           │   ├── monitoring.py  # Prometheus 指标采集
│           │   ├── models.py      # Pydantic 请求/响应模型
│           │   └── routes/        # 业务路由
│           │       ├── auth.py    # 注册 / 登录
│           │       ├── tests.py   # 护栏评估 / 历史 / 统计
│           │       └── stats.py   # 图表 / 概览数据
│           ├── config/
│           │   └── policy.yaml    # 护栏策略配置
│           ├── tests/
│           │   └── test_jailbreak.py
│           ├── .env               # 本地环境变量（不提交）
│           ├── .env.example       # 环境变量模板
│           ├── requirements.txt   # Python 依赖
│           └── Dockerfile
│
└── README.md                      # 本文件
```

## 技术栈

### 前端
- React 18 + TypeScript
- Tailwind CSS + Framer Motion
- Zustand + Axios + React Router
- ECharts 数据可视化

### 后端
- Python 3.10+
- FastAPI + Uvicorn
- LlamaFirewall 1.0.3（Meta PurpleLlama）
  - Prompt Guard 2（`meta-llama/Llama-Prompt-Guard-2-86M`）
  - CodeShield（CWE 漏洞检测）
- SQLAlchemy 2.x + aiomysql（异步 MySQL）
- passlib + bcrypt（密码哈希）
- python-jose（JWT）
- structlog（结构化日志）

### 数据库
- MySQL 8.0+
- 数据库名：`agentshield`

## API 端点

### 认证
```
POST /api/auth/register    # 用户注册
POST /api/auth/login       # 用户登录
```

### 测试与护栏评估
```
GET  /api/tests/categories  # 获取风险类别
POST /api/tests/evaluate    # ★ 核心：AI 护栏评估
GET  /api/tests/history     # 获取测试历史
GET  /api/tests/stats       # 按风险等级统计
```

### 统计与图表
```
GET /api/stats/charts       # 风险分布 + 分类图表
GET /api/stats/overview     # 总量 / 危险数 / 平均分
```

### 原始聊天接口（含护栏）
```
POST /api/v1/chat           # 完整对话（输入扫描 + 推理 + 输出扫描）
GET  /health                # 健康检查
```

## 数据库表

| 表名 | 说明 |
|------|------|
| `users` | 用户信息 |
| `risk_categories` | 风险类别 |
| `test_cases` | 预设测试用例 |
| `test_results` | 测试结果（含护栏扫描详情）|
| `audit_logs` | LlamaFirewall 审计日志 |

## 环境配置

`back/src/Llama Shield/.env` 关键配置项：

```env
# MySQL
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=agentshield
MYSQL_USER=root
MYSQL_PASSWORD=123456

# JWT（与前端保持一致）
JWT_SECRET=your-secret-key-change-in-production

# LlamaFirewall
LLAMAFIREWALL_MODE=strict
LLAMAFIREWALL_ENABLE_INPUT_SCAN=true
LLAMAFIREWALL_ENABLE_OUTPUT_SCAN=true

# 可选：MiniMax API 推理
USE_MINIMAX_API=false
MINIMAX_API_KEY=

# HuggingFace Token（Prompt Guard 模型下载）
HF_TOKEN=
```

## LlamaFirewall 防护层

| Scanner | 检测目标 | 触发条件 |
|---------|---------|----------|
| **Prompt Guard** | 越狱提示词、Prompt 注入攻击 | 用户输入扫描 |
| **CodeShield** | CWE 代码安全漏洞 | 模型输出扫描 |
| **Alignment Check** | 多轮目标劫持（实验性）| 默认关闭 |

风险等级映射：
- `score ≥ 0.7` 或 `is_blocked = true` → **critical**
- `score ≥ 0.4` → **high**  
- `score ≥ 0.0` → **medium / low**

## 常用命令

```bash
# 启动后端（开发模式，自动热重载）
cd "back/src/Llama Shield"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 启动前端
cd front
npm run dev

# 初始化数据库示例数据（使用 Prisma seed）
cd back
npm run prisma:seed

# 运行越狱测试基准
cd "back/src/Llama Shield"
pytest tests/test_jailbreak.py -v
```

## 参考资源

- [LlamaFirewall PyPI](https://pypi.org/project/llamafirewall/)
- [PurpleLlama GitHub](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [LlamaFirewall 论文](https://arxiv.org/pdf/2505.03574.pdf)

## 许可证

MIT
