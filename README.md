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

### 1. 数据库迁移和初始化

**自动初始化（推荐）**
```bash
bash init-db.sh
```

**手动初始化**
```bash
cd back

# 运行 Prisma 迁移（创建/更新表）
npm run prisma:migrate dev --name add_dataset_test_results

# 初始化数据（插入默认分类和测试用例）
npm run prisma:seed
```

### 2. 配置测试模式

在 `back/.env` 中配置：

```env
# 启用模拟模式（默认）- 快速生成测试结果
USE_MOCK_MODE=true
MOCK_DELAY=500

# 或启用真实模式 - 调用 Llama Shield API
# USE_MOCK_MODE=false
```

### 3. 启动 Llama Shield (AI 检测服务)

```bash
cd back/src/Llama Shield

# 安装依赖
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

# 启动服务
python -m app.main
```

### 3. 启动 Express 后端 (API 网关)

```bash
cd back
npm install
npm run dev
```

### 4. 启动前端

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
GET  /api/tests/categories      # 获取风险类别
POST /api/tests/evaluate        # AI 护栏评估
GET  /api/tests/history         # 获取测试历史（单条+数据集）
GET  /api/tests/result/:id      # 获取单条测试详情
POST /api/tests/dataset-test    # 保存数据集测试结果
GET  /api/tests/dataset-result/:id  # 获取数据集测试详情
GET  /api/tests/stats           # 按风险等级统计
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
| `test_results` | 单条测试结果 |
| `dataset_test_results` | 数据集测试结果 |

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

## 单条提示词测试模拟脚本

### 功能说明

已为项目添加了单条提示词测试的模拟脚本，可以生成模拟的测试结果：

- **自动风险检测** - 检测输入中的风险关键词
- **风险评分计算** - 基于多个因素计算风险评分（0-1）
- **风险等级划分** - 自动确定风险等级（low/medium/high/critical）
- **详细报告生成** - 生成详细的评估报告
- **模式切换** - 支持在模拟模式和真实模式之间切换

### 模式配置

在 `back/.env` 中配置：

```env
# 模拟模式（默认）- 快速生成测试结果
USE_MOCK_MODE=true
MOCK_DELAY=500              # 模拟延迟（毫秒）
VERBOSE_MODE=false          # 详细日志

# 或切换到真实模式
# USE_MOCK_MODE=false
```

### 风险关键词库

模拟脚本包含以下风险关键词：

- **越狱**: DAN, unrestricted, ignore, bypass, override, pretend, roleplay
- **暴力**: harm, kill, attack, weapon, bomb, explosive, assault
- **非法**: hack, crack, steal, fraud, money laundering, drug
- **偏见**: inferior, superior, stereotype, racist, sexist, discriminate
- **不雅**: damn, hell, crap, shit, fuck, ass
- **不道德**: cheat, deceive, manipulate, exploit, abuse

### 集成接口

模拟脚本已集成到以下接口：

1. **自定义风险评估界面** - 单条提示词测试
2. **示例体验界面** - 所有风险类别的测试

两个界面都会显示当前的测试模式（模拟/真实）。

### 详细配置

详见 [MOCK_TEST_GUIDE.md](./MOCK_TEST_GUIDE.md)

---

## 历史记录功能

### 功能说明

自定义风险评估界面支持完整的历史记录功能：

- **单条测试记录** - 自动保存每次提示词测试结果
- **数据集测试记录** - 保存批量测试的统计数据和图表
- **历史记录列表** - 分类显示所有测试记录（单条/数据集）
- **详情查看** - 点击查看完整的测试信息和可视化图表
- **权限控制** - 用户只能查看自己的测试记录

### 使用流程

#### 单条测试
1. 在"用户输入"区域输入提示词
2. 点击"评估"按钮
3. 查看评估结果
4. 结果自动保存到历史记录

#### 数据集测试
1. 在"数据集测试"区域上传文件（.csv/.json/.jsonl/.txt）
2. 点击"开始测试"按钮
3. 等待测试完成，查看统计结果和图表
4. 结果自动保存到历史记录

#### 查看历史
1. 点击右上角"历史记录"按钮
2. 查看历史记录列表
3. 点击任意记录查看详情
4. 在详情模态中查看完整信息和图表

### 数据可视化

数据集测试详情包含 4 个 ECharts 图表：
- 风险等级分布（饼图）
- 风险类别分布（横向柱状图）
- 风险评分分布（直方图）
- 通过 vs 拦截对比（堆积柱状图）

---

## 参考资源

- [LlamaFirewall PyPI](https://pypi.org/project/llamafirewall/)
- [PurpleLlama GitHub](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [MiniMax API](https://platform.minimaxi.com/)

---

## 故障排除

### 数据集测试保存失败 - 外键约束错误

**症状**：保存数据集测试时出现 "Foreign key constraint violated: categoryId" 错误

**原因**：数据库中没有对应的分类数据

**解决方案**：

1. **重新初始化数据库**
   ```bash
   cd back
   npm run prisma:migrate dev
   npm run prisma:seed
   ```

2. **或手动执行 SQL 迁移**
   ```bash
   mysql -u root -p agentshield < migration.sql
   ```

3. **验证分类数据**
   ```bash
   mysql -u root -p agentshield
   > SELECT * FROM risk_categories;
   ```

### 示例体验界面无法加载

**症状**：示例体验页面显示空白或加载失败

**解决方案**：

1. **检查后端服务**
   ```bash
   # 检查后端是否运行
   curl http://localhost:3001/health
   ```

2. **检查数据库初始化**
   ```bash
   cd back
   npm run prisma:migrate dev
   npm run prisma:seed
   ```

3. **查看浏览器控制台**
   - 按 F12 打开开发者工具
   - 查看 Console 标签中的错误信息
   - 查看 Network 标签中的 API 请求

4. **重启服务**
   ```bash
   # 重启后端
   cd back && npm run dev

   # 重启前端
   cd front && npm run dev
   ```

### 历史记录无法保存

**症状**：测试完成后历史记录中没有新记录

**解决方案**：

1. **检查数据库连接**
   ```bash
   # 验证 DATABASE_URL 环境变量
   echo $DATABASE_URL
   ```

2. **检查数据库迁移**
   ```bash
   cd back
   npm run prisma:migrate dev
   ```

3. **查看后端日志**
   - 检查后端控制台是否有错误信息
   - 查看 Prisma 的 SQL 错误

### API 返回 401 错误

**症状**：API 调用返回 "Unauthorized" 错误

**解决方案**：

1. **确保已登录**
   - 检查浏览器 localStorage 中是否有 token
   - 重新登录

2. **检查 JWT 配置**
   ```bash
   # 验证 JWT_SECRET 环境变量
   echo $JWT_SECRET
   ```

3. **清除缓存**
   - 清除浏览器 localStorage
   - 清除浏览器 cookies
   - 重新登录

---

## 许可证

MIT
