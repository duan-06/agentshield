# AgentShield Backend

Node.js + Express + TypeScript 后端服务，提供 AI 安全护栏系统的 API。

## 功能特性

- 🔐 JWT 认证系统
- 📝 用户管理（注册/登录）
- 🧪 测试评估 API
- 📊 数据统计和分析
- 🗄️ MySQL 数据库集成

## 技术栈

- Node.js
- Express
- TypeScript
- Prisma ORM
- MySQL
- JWT
- Bcrypt

## 快速开始

```bash
npm install
npm run prisma:generate
npm run prisma:migrate
npm run dev
```

## 环境配置

创建 `.env` 文件：

```
DATABASE_URL="mysql://root:password@localhost:3306/agentshield"
JWT_SECRET="your-secret-key-change-in-production"
PORT=3001
NODE_ENV="development"
```

## API 端点

### 认证
- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户登录

### 测试
- `GET /api/tests/categories` - 获取风险类别
- `POST /api/tests/evaluate` - 评估测试
- `GET /api/tests/history` - 获取测试历史
- `GET /api/tests/stats` - 获取统计数据

### 统计
- `GET /api/stats/charts` - 获取图表数据
- `GET /api/stats/overview` - 获取概览数据

## 数据库设计

- `users` - 用户表
- `risk_categories` - 风险类别表
- `test_cases` - 测试用例表
- `test_results` - 测试结果表
