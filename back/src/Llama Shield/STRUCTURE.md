# Llama Shield - 基于 Meta PurpleLlama 的 LLM 安全防护系统

## 项目结构

```
llama-shield/
├── .env.example
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── README.md
├── logs.md
├── difficulties.md
├── architecture.md
├── module_logs.md
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── firewall.py
│   ├── database.py
│   ├── monitoring.py
│   └── models.py
├── config/
│   └── policy.yaml
├── k8s/
│   ├── deployment.yaml
│   ├── service.yaml
│   └── hpa.yaml
└── tests/
    ├── __init__.py
    └── test_jailbreak.py
```
