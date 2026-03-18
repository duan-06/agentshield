# Llama Shield - AI 安全护栏服务

基于 Meta PurpleLlama/LlamaFirewall 的 AI 安全检测服务，提供越狱检测、代码安全检测、目标劫持检测等功能。

## 功能特性

- **多层防护**: Prompt Guard、CodeShield、Alignment Check
- **AI 推理**: 支持 MiniMax API
- **完整审计**: 请求日志记录
- **实时监控**: 指标采集

## 快速开始

### 安装依赖

```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```

### 启动服务

```bash
python -m app.main
```

服务地址: `http://localhost:8000`

## 目录结构

```
Llama Shield/
├── app/
│   ├── main.py            # FastAPI 入口
│   ├── firewall.py        # 核心防护逻辑
│   ├── db.py            # MySQL 连接
│   ├── db_models.py     # 数据模型
│   ├── models.py        # Pydantic 模型
│   └── monitoring.py    # 监控
├── config/
│   └── policy.yaml      # 策略配置
├── .env                 # 环境变量
├── requirements.txt     # Python 依赖
└── docker-compose.yml  # Docker 配置
```

## 环境变量

```env
# MySQL
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=agentshield
MYSQL_USER=root
MYSQL_PASSWORD=

# JWT
JWT_SECRET=your-secret-key

# LlamaFirewall
LLAMAFIREWALL_MODE=strict
LLAMAFIREWALL_ENABLE_INPUT_SCAN=true
LLAMAFIREWALL_ENABLE_OUTPUT_SCAN=true
LLAMAFIREWALL_ENABLE_ALIGNMENT_CHECK=true

# MiniMax API
USE_MINIMAX_API=true
MINIMAX_API_KEY=your-api-key
MINIMAX_MODEL=MiniMax-M2.5
```

## API 端点

### 聊天接口（含护栏）

```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "messages": [
      {"role": "user", "content": "你好"}
    ],
    "temperature": 0.7,
    "max_tokens": 2048
  }'
```

### 健康检查

```bash
curl http://localhost:8000/health
```

### 统计信息

```bash
curl http://localhost:8000/api/v1/stats
```

## LlamaFirewall 组件

| Scanner | 检测目标 |
|---------|---------|
| Prompt Guard | 越狱提示词、注入攻击 |
| CodeShield | CWE 代码安全漏洞 |
| Alignment Check | 目标劫持检测 |

## 参考资源

- [LlamaFirewall PyPI](https://pypi.org/project/llamafirewall/)
- [PurpleLlama GitHub](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)

## 许可证

MIT
