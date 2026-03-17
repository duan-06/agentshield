# AgentShield - AI 安全护栏系统

一套完整的 AI 安全护栏解决方案，用于防护注入攻击、越狱攻击、有害内容过滤等。

## 快速开始

### 后端启动
```bash
cd back
npm install
cp .env.example .env
# 编辑 .env 配置数据库
npm run prisma:generate
npm run prisma:migrate
npm run prisma:seed
npm run dev
```

### 前端启动
```bash
cd front
npm install
npm run dev
```

访问 `http://localhost:3000`

## 项目结构

```
agentshield/
├── front/                    # React 前端应用
│   ├── src/
│   │   ├── pages/           # 4 个页面组件
│   │   ├── services/        # API 服务
│   │   ├── store/           # 状态管理
│   │   └── App.tsx
│   └── package.json
│
├── back/                     # Express 后端应用
│   ├── src/
│   │   ├── routes/          # API 路由
│   │   ├── middleware/      # 认证中间件
│   │   ├── validators/      # 数据验证
│   │   └── index.ts
│   ├── prisma/
│   │   ├── schema.prisma    # 数据库模型
│   │   └── seed.ts          # 初始化脚本
│   └── package.json
│
└── 文档
    ├── README.md            # 本文件
    └── DEPLOYMENT.md        # 部署指南
```

## 技术栈

### 前端
- React 18 + TypeScript
- Tailwind CSS + Framer Motion
- Zustand + Axios + React Router

### 后端
- Express + TypeScript
- Prisma ORM + MySQL
- JWT + Bcrypt + Joi

## 核心功能

### 用户认证
- 注册/登录（用户名仅英文数字，密码至少8字符）
- JWT token 认证
- 密码 bcrypt 加密

### 测试功能
- **Try Example**: 预设测试用例
- **Bring Your Own Risk**: 自定义测试
- 历史记录管理
- 风险等级分类

### 数据管理
- 用户数据存储
- 测试结果记录
- 统计数据生成

## API 端点

### 认证
```
POST /api/auth/register
POST /api/auth/login
```

### 测试
```
GET /api/tests/categories
POST /api/tests/evaluate
GET /api/tests/history
GET /api/tests/stats
```

### 统计
```
GET /api/stats/charts
GET /api/stats/overview
```

## 数据库表

| 表名 | 说明 |
|------|------|
| users | 用户信息 |
| risk_categories | 风险类别 |
| test_cases | 测试用例 |
| test_results | 测试结果 |

## 环境配置

```
DATABASE_URL=mysql://root:password@localhost:3306/agentshield
JWT_SECRET=your-secret-key
PORT=3001
NODE_ENV=development
```

## 常用命令

### 后端
```bash
npm run dev              # 启动开发服务器
npm run build            # 构建生产版本
npm run prisma:migrate   # 运行数据库迁移
npm run prisma:seed      # 初始化示例数据
npm run prisma:studio    # 打开 Prisma Studio
```

### 前端
```bash
npm run dev              # 启动开发服务器
npm run build            # 构建生产版本
npm run preview          # 预览生产版本
```

## 后续开发 - AI 护栏系统集成

### 系统架构

AI 护栏系统放在 `back/src/services/aiShield/` 目录：

```
back/src/services/
├── aiShield/              # AI 护栏系统 (从 GitHub 克隆)
│   ├── src/
│   │   ├── index.ts       # 导出接口
│   │   ├── detector.ts    # 威胁检测
│   │   ├── models/        # 检测模型
│   │   └── utils/         # 工具函数
│   └── package.json
└── api.ts
```

### 集成步骤

1. **克隆护栏系统**
   ```bash
   cd back/src/services
   git clone <your-ai-shield-repo> aiShield
   cd aiShield && npm install
   ```

2. **在测试路由中使用**
   ```typescript
   // back/src/routes/tests.ts
   import { aiShield } from '../services/aiShield';
   
   router.post('/evaluate', authMiddleware, async (req, res) => {
     const evaluation = await aiShield.evaluate(input, categoryId);
     const testResult = await prisma.testResult.create({
       data: {
         userId: req.userId,
         categoryId,
         input,
         output: JSON.stringify(evaluation.details),
         riskLevel: evaluation.riskLevel,
         riskScore: evaluation.riskScore,
       },
     });
     res.json({ success: true, data: testResult });
   });
   ```

3. **护栏系统接口规范**
   ```typescript
   interface EvaluationResult {
     riskLevel: 'low' | 'medium' | 'high' | 'critical';
     riskScore: number;  // 0-1
     threats: string[];
     details: Record<string, any>;
   }

   interface AIShield {
     evaluate(input: string, categoryId: number): Promise<EvaluationResult>;
     detectPromptInjection(input: string): Promise<boolean>;
     detectJailbreak(input: string): Promise<boolean>;
     filterHarmfulContent(input: string): Promise<string>;
   }
   ```

## 详细文档

- [部署指南](./DEPLOYMENT.md) - 完整的部署和测试说明

## 许可证

MIT
