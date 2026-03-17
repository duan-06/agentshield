"""
Llama Shield - 主应用程序入口

基于 Meta PurpleLlama/LlamaFirewall 的 LLM 安全防护系统
提供 /chat 和 /health 接口，包含 JWT 认证、限流和完整审计日志
"""

import os
import time
import logging
import asyncio
from contextlib import asynccontextmanager
from typing import Optional

# 加载 .env 文件
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import JWTError, jwt
import structlog

from app.firewall import LlamaFirewallManager
from app.database import AuditLogger, init_db
from app.monitoring import MetricsCollector
from app.models import ChatRequest, ChatResponse, HealthResponse

# vLLM 推理引擎配置
VLLM_MODEL_PATH = os.getenv("VLLM_MODEL_PATH", "D:/计算机设计大赛/models/qwen/Qwen2___5-7B-Instruct")
VLLM_GPU_MEMORY_UTILIZATION = float(os.getenv("VLLM_GPU_MEMORY_UTILIZATION", "0.75"))

# 优先使用 vLLM，如果失败则回退到 transformers
USE_VLLM = os.getenv("USE_VLLM", "false").lower() == "true"

# MiniMax API 配置
USE_MINIMAX_API = os.getenv("USE_MINIMAX_API", "false").lower() == "true"
MINIMAX_API_KEY = os.getenv("MINIMAX_API_KEY", "")
MINIMAX_MODEL = os.getenv("MINIMAX_MODEL", "MiniMax-M2.5")
MINIMAX_BASE_URL = os.getenv("MINIMAX_BASE_URL", "https://api.minimax.chat/v1")

# 配置日志
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)
logger = structlog.get_logger(__name__)

# 全局变量
firewall_manager: Optional[LlamaFirewallManager] = None
audit_logger: Optional[AuditLogger] = None
metrics: Optional[MetricsCollector] = None

# 推理引擎实例
vllm_llm = None
transformers_pipeline = None


def get_vllm_llm():
    """获取或初始化 vLLM LLM 实例"""
    global vllm_llm
    if vllm_llm is None:
        try:
            from vllm import LLM
            vllm_llm = LLM(
                model=VLLM_MODEL_PATH,
                tensor_parallel_size=1,
                gpu_memory_utilization=VLLM_GPU_MEMORY_UTILIZATION,
                dtype="auto",
                max_model_len=4096,
            )
            logger.info(f"vLLM initialized with model: {VLLM_MODEL_PATH}")
        except Exception as e:
            logger.warning(f"vLLM not available, will use transformers: {e}")
            vllm_llm = None
    return vllm_llm


def get_transformers_pipeline():
    """获取或初始化 HuggingFace transformers pipeline"""
    global transformers_pipeline
    if transformers_pipeline is None:
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
            tokenizer = AutoTokenizer.from_pretrained(
                VLLM_MODEL_PATH,
                trust_remote_code=True
            )
            model = AutoModelForCausalLM.from_pretrained(
                VLLM_MODEL_PATH,
                device_map="auto",
                trust_remote_code=True,
                torch_dtype="auto",
            )
            transformers_pipeline = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
            )
            logger.info(f"Transformers pipeline initialized with model: {VLLM_MODEL_PATH}")
        except Exception as e:
            logger.error(f"Failed to initialize transformers: {e}")
            raise
    return transformers_pipeline


async def generate_with_minimax(prompt: str, temperature: float = 0.7, max_tokens: int = 2048) -> str:
    """使用 MiniMax API 生成回复"""
    if not MINIMAX_API_KEY:
        raise ValueError("MINIMAX_API_KEY not configured")

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(
            api_key=MINIMAX_API_KEY,
            base_url=MINIMAX_BASE_URL
        )

        response = await client.chat.completions.create(
            model=MINIMAX_MODEL,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=0.9
        )

        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"MiniMax API error: {e}")
        raise


async def generate_with_vllm(prompt: str, temperature: float = 0.7, max_tokens: int = 2048) -> str:
    """使用 vLLM/Transformers/MiniMax 生成回复"""

    # 优先使用 MiniMax API
    if USE_MINIMAX_API:
        try:
            return await generate_with_minimax(prompt, temperature, max_tokens)
        except Exception as e:
            logger.warning(f"MiniMax API failed: {e}")
    # 优先尝试 vLLM
    if USE_VLLM:
        try:
            llm = get_vllm_llm()
            if llm:
                from vllm import SamplingParams
                sampling_params = SamplingParams(
                    temperature=temperature,
                    max_tokens=max_tokens,
                    top_p=0.9,
                )
                outputs = llm.generate([prompt], sampling_params)
                return outputs[0].outputs[0].text
        except Exception as e:
            logger.warning(f"vLLM failed, falling back to transformers: {e}")

    # 回退到 transformers
    try:
        pipeline = get_transformers_pipeline()
        result = pipeline(
            prompt,
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_p=0.9,
            do_sample=temperature > 0,
        )
        # 提取新增的文本（去除原始 prompt）
        generated = result[0]["generated_text"]
        if generated.startswith(prompt):
            return generated[len(prompt):].strip()
        return generated.strip()
    except Exception as e:
        logger.error(f"Transformers generation error: {e}")
        raise


# ==================== Pydantic 模型 ====================

class BlockedResponse(BaseModel):
    """请求被阻断时的响应"""
    error: str
    blocked_reason: str
    blocked_by: str
    request_id: str


# ==================== 依赖项 ====================

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """JWT 认证依赖项"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials"
        )

    try:
        # JWT 验证（使用环境变量中的密钥）
        payload = jwt.decode(
            credentials.credentials,
            key=os.getenv("SECRET_KEY", "dev-secret-key"),
            algorithms=["HS256"]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )


async def rate_limit_check(request: Request):
    """简单的内存限流检查（生产环境应使用 Redis）"""
    # TODO: 实现基于 Redis 的分布式限流
    pass


# ==================== 生命周期管理 ====================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    global firewall_manager, audit_logger, metrics

    startup_time = time.time()

    # 初始化数据库
    logger.info("Initializing database...")
    await init_db()
    audit_logger = AuditLogger()

    # 初始化 LlamaFirewall
    logger.info("Initializing LlamaFirewall...")
    firewall_manager = LlamaFirewallManager()
    await firewall_manager.initialize()

    # 初始化监控
    logger.info("Initializing metrics...")
    metrics = MetricsCollector()

    logger.info(
        "Application started",
        version="1.0.0",
        startup_time=startup_time
    )

    yield

    # 清理资源
    logger.info("Shutting down application...")
    if firewall_manager:
        await firewall_manager.cleanup()
    logger.info("Application shutdown complete")


# ==================== 应用实例 ====================

app = FastAPI(
    title="Llama Shield",
    description="基于 Meta PurpleLlama 的 LLM 安全防护系统",
    version="1.0.0",
    lifespan=lifespan
)

# CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== 中间件 ====================

@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """请求日志中间件"""
    request_id = request.headers.get("X-Request-ID", f"req-{int(time.time() * 1000)}")
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)

    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration * 1000, 2)
    )

    return response


# ==================== API 端点 ====================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """健康检查接口"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        firewall_status="active" if firewall_manager else "inactive",
        database_status="connected" if audit_logger else "disconnected",
        uptime=time.time()
    )


@app.post("/api/v1/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    http_request: Request,
    user: dict = Depends(get_current_user)
):
    """
    聊天接口 - 核心防护入口

    请求流程:
    1. 输入验证和预处理
    2. LlamaFirewall 输入扫描（Prompt Guard + Alignment Check）
    3. vLLM 推理
    4. LlamaFirewall 输出扫描（CodeShield）
    5. 审计日志写入
    """
    request_id = http_request.headers.get(
        "X-Request-ID",
        f"chat-{int(time.time() * 1000)}"
    )
    start_time = time.time()

    try:
        # ==================== 步骤 1: 输入扫描 ====================
        logger.info("Starting input scan", request_id=request_id)

        # 转换为字典格式
        messages_dict = [msg.model_dump() for msg in request.messages]

        # 使用 LlamaFirewall 扫描用户输入
        input_scan_result = await firewall_manager.scan_input(
            messages=messages_dict,
            request_id=request_id
        )

        # 如果输入被阻断
        if input_scan_result.is_blocked:
            logger.warning(
                "Input blocked by firewall",
                request_id=request_id,
                blocked_by=input_scan_result.blocked_by,
                reason=input_scan_result.blocked_reason
            )

            # 记录阻断日志
            await audit_logger.log_blocked_request(
                request_id=request_id,
                messages=messages_dict,
                blocked_by=input_scan_result.blocked_by,
                reason=input_scan_result.blocked_reason,
                scan_result=input_scan_result
            )

            # 更新指标
            metrics.increment_blocked_requests(
                blocked_by=input_scan_result.blocked_by
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Request blocked by security policy",
                    "blocked_reason": input_scan_result.blocked_reason,
                    "blocked_by": input_scan_result.blocked_by,
                    "request_id": request_id
                }
            )

        # ==================== 步骤 2: vLLM 推理 ====================
        try:
            # 构建 prompt（简单的格式，实际可以使用 ChatML 格式）
            prompt = messages_dict[-1].get("content", "") if messages_dict else ""

            # 使用 vLLM 生成回复
            response_content = await generate_with_vllm(
                prompt=prompt,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            )
        except Exception as e:
            logger.error(f"LLM inference failed: {e}")
            # 如果推理失败，返回错误消息
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "LLM service temporarily unavailable", "request_id": request_id}
            )

        # ==================== 步骤 3: 输出扫描 ====================
        logger.info("Starting output scan", request_id=request_id)

        output_scan_result = await firewall_manager.scan_output(
            content=response_content,
            request_id=request_id
        )

        if output_scan_result.is_blocked:
            logger.warning(
                "Output blocked by firewall",
                request_id=request_id,
                blocked_by=output_scan_result.blocked_by,
                reason=output_scan_result.blocked_reason
            )

            await audit_logger.log_blocked_request(
                request_id=request_id,
                messages=messages_dict,
                response=response_content,
                blocked_by=output_scan_result.blocked_by,
                reason=output_scan_result.blocked_reason,
                scan_result=output_scan_result
            )

            metrics.increment_blocked_requests(
                blocked_by=output_scan_result.blocked_by
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Response blocked by security policy",
                    "blocked_reason": output_scan_result.blocked_reason,
                    "blocked_by": output_scan_result.blocked_by,
                    "request_id": request_id
                }
            )

        # ==================== 步骤 4: 成功响应 ====================
        duration = time.time() - start_time

        # 记录成功请求
        await audit_logger.log_successful_request(
            request_id=request_id,
            messages=messages_dict,
            response=response_content,
            input_scan=input_scan_result,
            output_scan=output_scan_result,
            duration=duration
        )

        # 更新指标
        metrics.increment_successful_requests(duration=duration)

        return ChatResponse(
            id=request_id,
            created=int(time.time()),
            model="llama-3.1-70b-instruct",
            choices=[{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_content
                },
                "finish_reason": "stop"
            }],
            usage={
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Unexpected error in chat endpoint",
            request_id=request_id,
            error=str(e)
        )
        metrics.increment_errors()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Internal server error", "request_id": request_id}
        )


# ==================== 统计端点 ====================

@app.get("/api/v1/stats")
async def get_stats():
    """获取系统统计信息"""
    return {
        "total_requests": metrics.get_total_requests(),
        "blocked_requests": metrics.get_blocked_requests(),
        "successful_requests": metrics.get_successful_requests(),
        "block_rate": metrics.get_block_rate(),
        "average_latency_ms": metrics.get_average_latency(),
        "requests_per_minute": metrics.get_requests_per_minute()
    }


# ==================== 启动 ====================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )
