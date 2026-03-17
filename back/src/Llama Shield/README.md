# Llama Shield - 基于 Meta PurpleLlama 的 LLM 安全防护系统

## 功能特性

- **多层防护**: Prompt Guard、CodeShield、Alignment Check（实验性）
- **高性能**: 支持 >200 QPS（4×A100）
- **完整审计**: 所有请求记录 PostgreSQL
- **实时监控**: Prometheus + Grafana
- **容器化**: Docker + Kubernetes 支持

## 系统架构

```
客户端 / API Gateway
↓ (HTTPS + 限流)
FastAPI 服务层（入口 + JWT认证 + 限流）
↓
LlamaFirewall 中间件（核心防护引擎）
├── Prompt Guard (meta-llama/Llama-Prompt-Guard-2-86M)
├── CodeShield (codeshield 包)
└── Alignment Check (实验性, Llama-4 + Together.ai API)
↓（仅当 decision == "ALLOW" 时才继续）
vLLM 推理服务（Meta-Llama-3.1-70B-Instruct 或 3.2 系列）
↓
最终响应 + 完整审计日志入库
```

## 快速开始

### 前置要求

- Python 3.10+
- PostgreSQL 16+
- Redis 7+
- Docker & Docker Compose
- GPU（可选，用于 vLLM 推理）
- HuggingFace Token（用于下载 Prompt Guard 模型）

### 安装

1. 克隆项目：
```bash
git clone https://github.com/your-repo/llama-shield.git
cd llama-shield
```

2. 配置环境：
```bash
cp .env.example .env
# 编辑 .env 填入实际值
```

3. 安装依赖（使用清华源）：
```bash
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```

### 下载模型

#### 方式 1：HuggingFace Hub（首选）

```bash
# 设置 HuggingFace Token（必需，用于下载 Prompt Guard 模型）
export HF_TOKEN=your_token_here

# 登录 HuggingFace
huggingface-cli login
# 或在代码中：
from huggingface_hub import login
login(token="your_hf_token")
```

#### 方式 2：ModelScope（国内备选）

```bash
# 安装 ModelScope
pip install modelscope

# 下载模型
from modelscope.hub.snapshot_download import snapshot_download
snapshot_download('LLM-Research/Meta-Llama-3.1-70B-Instruct', cache_dir='./models')
```

### 启动服务

#### 开发环境（Docker Compose）

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f llama-shield

# 停止服务
docker-compose down
```

#### 本地开发

```bash
# 启动 PostgreSQL 和 Redis
docker run -d -p 5432:5432 -e POSTGRES_DB=llama_shield \
  -e POSTGRES_USER=llama_shield -e POSTGRES_PASSWORD=pass postgres:16

docker run -d -p 6379:6379 redis:7

# 启动应用
python -m app.main
```

## LlamaFirewall 组件

### Scanner 类型

| Scanner | 模型 | 用途 | 必需 |
|---------|------|------|------|
| **Prompt Guard** | `meta-llama/Llama-Prompt-Guard-2-86M` | 越狱/注入检测 | ✅ |
| **Code Shield** | `codeshield` 包 | 代码安全漏洞检测 | ✅ |
| **Alignment Check** | `Llama-4-Maverick` + Together.ai API | 多轮目标劫持检测 | ❌ (实验性) |
| **PII Detection** | - | PII 信息检测 | ❌ |
| **Hidden ASCII** | - | 隐藏字符检测 | ❌ |

### 环境变量

```bash
# HuggingFace（必需）
HF_TOKEN=your_hf_token

# Together.ai（Alignment Check 实验性功能可选）
TOGETHER_API_KEY=your_together_api_key
```

## API 使用

### 聊天接口

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

### 监控指标

```bash
curl http://localhost:9090/metrics
```

## 测试

### 运行 CyberSecEval 基准测试

```bash
# 安装测试依赖
pip install pytest pytest-asyncio pytest-cov

# 运行测试
pytest tests/test_jailbreak.py -v

# 查看 ASR 指标
pytest tests/test_jailbreak.py::TestAttackSuccessRate -v
```

预期结果：
- **ASR < 5%**: 攻击成功率低于 5%
- **FPR < 10%**: 误报率低于 10%

## 性能指标

| 指标 | 目标值 |
|------|--------|
| QPS | >200 (4×A100) |
| 延迟 P99 | <500ms |
| 拦截率 | >95% |
| ASR | <5% |
| FPR | <10% |

## 配置

详见 [config/policy.yaml](config/policy.yaml)

主要配置项：
- `LLAMAFIREWALL_MODE`: strict/balanced/permissive
- `LLAMAFIREWALL_BLOCK_THRESHOLD`: 阻断阈值 (0.0-1.0)
- 各类 Scanner 的开关和阈值

## 监控

访问 Grafana: http://localhost:3000
- 默认账号: admin/admin

预设仪表板：
- 请求量监控
- 拦截统计
- 延迟分布
- ASR/FPR 指标

## Kubernetes 部署

```bash
# 创建命名空间
kubectl create namespace llama-shield

# 应用配置
kubectl apply -f k8s/

# 查看状态
kubectl get pods -n llama-shield
```

## 官方资源

- **PyPI**: https://pypi.org/project/llamafirewall/
- **GitHub**: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
- **文档**: https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
- **论文**: https://arxiv.org/pdf/2505.03574.pdf

## 许可证

MIT License
