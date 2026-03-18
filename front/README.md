# AgentShield 前端

基于 **React 18 + TypeScript** 的现代化 Web 应用，提供 AI 安全护栏系统的可视化界面。

## 快速启动

```bash
npm install
npm run dev
```

访问 `http://localhost:5173`

> 后端服务需在 `http://localhost:8000` 运行（FastAPI）

## 项目结构

```
src/
├── pages/           # 页面组件
├── components/      # 可复用组件
├── services/        # API 请求封装（axios）
├── store/           # Zustand 全局状态
├── App.tsx          # 路由配置
└── main.tsx         # 入口文件
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

`vite.config.ts` 中配置后端代理，默认指向 `http://localhost:8000`（FastAPI）：

```ts
server: {
  proxy: {
    '/api': 'http://localhost:8000',
  }
}
```

## 常用命令

```bash
npm run dev        # 开发模式（热更新）
npm run build      # 构建生产版本
npm run preview    # 预览生产版本
```
