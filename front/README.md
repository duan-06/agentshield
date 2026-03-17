# AgentShield Frontend

现代化的 React + TypeScript 前端应用，提供 AI 安全护栏系统的用户界面。

## 功能特性

- 🎨 现代化的深色主题 UI
- 🔐 用户认证系统（登录/注册）
- 📊 实时测试评估
- 📈 历史记录和数据可视化
- ⚡ 响应式设计

## 技术栈

- React 18
- TypeScript
- Tailwind CSS
- Framer Motion
- Zustand
- Axios
- ECharts

## 快速开始

```bash
npm install
npm run dev
```

## 项目结构

```
src/
├── pages/           # 页面组件
├── components/      # 可复用组件
├── services/        # API 服务
├── store/          # 状态管理
├── App.tsx         # 主应用
└── main.tsx        # 入口文件
```

## 环境配置

后端 API 代理配置在 `vite.config.ts` 中，默认指向 `http://localhost:3001`。
