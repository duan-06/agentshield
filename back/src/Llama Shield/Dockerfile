# Llama Shield - 生产镜像
# 多阶段构建，强制使用清华镜像源

# ==================== 阶段 1: 基础镜像 ====================
FROM python:3.10-slim as base

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# ==================== 阶段 2: 构建依赖 ====================
FROM base as builder

# 安装构建工具
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# 创建虚拟环境
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 安装依赖（使用清华源）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ==================== 阶段 3: 运行镜像 ====================
FROM base

# 复制虚拟环境
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制应用代码
COPY app /app/app
COPY config /app/config

# 创建日志目录
RUN mkdir -p /app/logs

# 设置非 root 用户
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# ==================== 暴露端口 ====================
EXPOSE 8000 9090

# ==================== 健康检查 ====================
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ==================== 启动命令 ====================
CMD ["gunicorn", "app.main:app", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
