# AgentShield 前端

基于 **React 18 + TypeScript** 的现代化 Web 应用，提供 AI 安全护栏系统的可视化界面。

## 快速启动

```bash
npm install
npm run dev
```

访问 `http://localhost:5173`

## 项目结构

```
src/
├── pages/              # 页面组件
│   ├── LandingPage.tsx
│   ├── LoginPage.tsx
│   ├── BringYourOwnPage.tsx
│   └── TryExamplePage.tsx
├── components/         # 可复用组件
│   └── Navbar.tsx
├── services/           # API 请求封装
│   └── api.ts
├── store/              # Zustand 全局状态
│   └── authStore.ts
├── App.tsx             # 路由配置
└── main.tsx            # 入口文件
```

## 技术栈

| 技术 | 用途 |
|------|------|
| React 18 + TypeScript | UI 框架 |
| Tailwind CSS | 样式 |
| Framer Motion | 动画 |
| Zustand | 状态管理 |
| Axios | HTTP 请求 |
| React Router | 路由 |
| ECharts | 图表可视化 |

## 环境配置

`vite.config.ts` 中配置后端代理，指向 Express 后端 (端口 3001)：

```ts
server: {
  proxy: {
    '/api': 'http://localhost:3001',
  }
}
```

## 常用命令

```bash
npm run dev        # 开发模式（热更新）
npm run build      # 构建生产版本
npm run preview    # 预览生产版本
```
