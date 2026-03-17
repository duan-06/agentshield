# Llama Shield 模块变更日志

## app/firewall.py
- **版本**: 1.0.0 -> 1.1.0
- **说明**: LlamaFirewall 核心防护引擎封装
- **API 状态**: ✅ 已基于官方源码和示例验证
- **主要变更**:
  - 完全重写，使用正确的 LlamaFirewall 1.0.3 API
  - ScannerType: 使用 PROMPT_GUARD, CODE_SHIELD, AGENT_ALIGNMENT
  - Decision: 使用 ScanDecision.BLOCK/ALLOW
  - 初始化: 使用 LlamaFirewall(scanners={Role: [...]})
  - 扫描: 使用 firewall.scan(input=Message, trace=Trace)
- **使用的模型**:
  - Prompt Guard: `meta-llama/Llama-Prompt-Guard-2-86M`
  - Code Shield: codeshield 包
  - Alignment Check: `Llama-4-Maverick-17B-128E-Instruct-FP8` (实验性)
- **初始化参数**:
  - scanners: {Role.USER: [...], Role.ASSISTANT: [...]}
- **官方文档**: https://meta-llama.github.io/PurpleLlama/LlamaFirewall/
- **GitHub**: https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall
- **变更历史**:
  - 1.0.0: 初始版本（基于假设 API）
  - 1.1.0: 修正 API，基于官方示例重写

---

## app/main.py
- **版本**: 1.0.0
- **说明**: FastAPI 主应用入口
- **功能**:
  - /chat 接口: 核心防护入口
  - /health 接口: 健康检查
  - /stats 接口: 统计信息
  - /metrics 接口: Prometheus 指标
- **依赖项**: firewall, database, monitoring
- **变更历史**: 初始版本

---

## app/database.py
- **版本**: 1.0.0
- **说明**: PostgreSQL 审计日志
- **数据表**:
  - AuditLog: 审计日志表
  - SessionTracking: 会话追踪表
- **功能**:
  - log_successful_request(): 记录成功请求
  - log_blocked_request(): 记录阻断请求
- **变更历史**: 初始版本

---

## app/monitoring.py
- **版本**: 1.0.0
- **说明**: Prometheus 指标收集
- **指标类型**:
  - TOTAL_REQUESTS: 总请求数
  - SUCCESSFUL_REQUESTS: 成功请求数
  - BLOCKED_REQUESTS: 阻断请求数
  - REQUEST_LATENCY: 请求延迟
- **变更历史**: 初始版本

---

## config/policy.yaml
- **版本**: 1.0.0
- **说明**: 安全策略配置文件
- **配置项**:
  - input_policy: 输入策略
  - output_policy: 输出策略
  - rate_limit: 限流配置
- **变更历史**: 初始版本

---

## tests/test_jailbreak.py
- **版本**: 1.0.0
- **说明**: CyberSecEval 越狱测试
- **测试类**:
  - TestJailbreakDetection: 越狱检测测试
  - TestAttackSuccessRate: ASR 计算测试
- **性能指标**:
  - ASR 目标: < 5%
  - FPR 目标: < 10%
- **变更历史**: 初始版本

---

## requirements.txt
- **版本**: 1.0.0
- **说明**: Python 依赖列表
- **核心依赖**:
  - llamafirewall==1.0.3 (官方版本)
  - fastapi, uvicorn, gunicorn
  - psycopg2-binary, asyncpg, sqlalchemy
  - redis, aioredis
  - prometheus-client, structlog
- **变更历史**:
  - 1.0.0: 初始版本
