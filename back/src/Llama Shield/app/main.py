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
from typing import Optional, List, Dict, Any

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
from app.db import init_db, close_db, write_audit_log
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
MINIMAX_MODEL = os.getenv("MINIMAX_MODEL", "minimax-m2.7")
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


class ScanRequest(BaseModel):
    """输入扫描请求"""
    messages: List[Dict[str, str]]


class ScanResponse(BaseModel):
    """输入扫描响应"""
    is_blocked: bool
    decision: str
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    score: float = 0.0


class BatchScanRequest(BaseModel):
    """批量输入扫描请求"""
    items: List[ScanRequest] = Field(default_factory=list)


class BatchScanItemResult(BaseModel):
    """批量输入扫描单条结果"""
    index: int
    is_blocked: bool
    decision: str
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    score: float = 0.0


class BatchScanResponse(BaseModel):
    """批量输入扫描响应"""
    results: List[BatchScanItemResult]


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
    global firewall_manager, metrics

    startup_time = time.time()

    # 初始化 MySQL 数据库
    logger.info("Initializing MySQL database...")
    from app.db import init_db as mysql_init_db, close_db
    await mysql_init_db()

    # 初始化 LlamaFirewall
    logger.info("Initializing LlamaFirewall...")
    firewall_manager = LlamaFirewallManager()
    await firewall_manager.initialize()

    # 初始化 LlamaGuard（有害内容检测）
    if os.getenv("LLAMA_GUARD_ENABLED", "true").lower() == "true":
        logger.info("Initializing LlamaGuard...")
        from app.firewall import initialize_llamaguard
        await initialize_llamaguard()

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
    await close_db()
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
        database_status="connected" if firewall_manager else "disconnected",
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
    user_id = user.get("sub") if user else None

    # 审计日志数据
    audit_messages = []
    audit_input_scan = None
    audit_response = None
    audit_output_scan = None
    audit_decision = "ALLOW"
    audit_blocked_by = None
    audit_blocked_reason = None

    try:
        # ==================== 步骤 1: 输入扫描 ====================
        logger.info("Starting input scan", request_id=request_id)

        # 转换为字典格式
        messages_dict = [msg.model_dump() for msg in request.messages]
        audit_messages = messages_dict

        # ==================== 步骤 1.1: 扫描工具返回结果 ====================
        tool_messages = [msg for msg in messages_dict if msg.get("role") == "tool"]
        if tool_messages:
            logger.info(f"Found {len(tool_messages)} tool messages, scanning for indirect injection", request_id=request_id)

            for idx, tool_msg in enumerate(tool_messages):
                tool_content = tool_msg.get("content", "")
                tool_name = tool_msg.get("name", "default")

                tool_scan_result = await firewall_manager.scan_tool_output_with_stackone(
                    tool_output=tool_content,
                    tool_name=tool_name
                )

                if tool_scan_result.is_blocked:
                    logger.warning(
                        "Tool output blocked by StackOne Defender",
                        request_id=request_id,
                        tool_index=idx,
                        tool_name=tool_name,
                        blocked_by=tool_scan_result.blocked_by,
                        reason=tool_scan_result.blocked_reason
                    )

                    metrics.increment_blocked_requests(blocked_by="StackOneDefender")

                    # 写入审计日志
                    audit_decision = "BLOCK"
                    audit_blocked_by = tool_scan_result.blocked_by
                    audit_blocked_reason = tool_scan_result.blocked_reason
                    await write_audit_log(
                        request_id=request_id,
                        user_id=user_id,
                        messages=audit_messages,
                        input_scan_result=audit_input_scan,
                        response=None,
                        output_scan_result=None,
                        decision=audit_decision,
                        blocked_by=audit_blocked_by,
                        blocked_reason=audit_blocked_reason,
                        duration_ms=int((time.time() - start_time) * 1000),
                    )

                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail={
                            "error": "Tool output blocked by security policy",
                            "blocked_reason": tool_scan_result.blocked_reason,
                            "blocked_by": "StackOneDefender",
                            "request_id": request_id
                        }
                    )

        # ==================== 步骤 1.2: 常规输入扫描 ====================
        input_scan_result = await firewall_manager.scan_input(
            messages=messages_dict,
            request_id=request_id
        )
        audit_input_scan = {
            "is_blocked": input_scan_result.is_blocked,
            "decision": input_scan_result.decision,
            "blocked_by": input_scan_result.blocked_by,
            "blocked_reason": input_scan_result.blocked_reason,
            "score": input_scan_result.score,
        }

        if input_scan_result.is_blocked:
            logger.warning(
                "Input blocked by firewall",
                request_id=request_id,
                blocked_by=input_scan_result.blocked_by,
                reason=input_scan_result.blocked_reason
            )

            metrics.increment_blocked_requests(blocked_by=input_scan_result.blocked_by)

            # 写入审计日志
            audit_decision = "BLOCK"
            audit_blocked_by = input_scan_result.blocked_by
            audit_blocked_reason = input_scan_result.blocked_reason
            await write_audit_log(
                request_id=request_id,
                user_id=user_id,
                messages=audit_messages,
                input_scan_result=audit_input_scan,
                response=None,
                output_scan_result=None,
                decision=audit_decision,
                blocked_by=audit_blocked_by,
                blocked_reason=audit_blocked_reason,
                duration_ms=int((time.time() - start_time) * 1000),
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
            prompt = messages_dict[-1].get("content", "") if messages_dict else ""

            response_content = await generate_with_vllm(
                prompt=prompt,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            )
        except Exception as e:
            logger.error(f"LLM inference failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "LLM service temporarily unavailable", "request_id": request_id}
            )

        audit_response = response_content

        # ==================== 步骤 3: 输出扫描 ====================
        enable_output_scan = os.getenv("LLAMAFIREWALL_ENABLE_OUTPUT_SCAN", "true").lower() == "true"

        if enable_output_scan:
            logger.info("Starting output scan", request_id=request_id)

            try:
                output_scan_result = await firewall_manager.scan_output(
                    content=response_content,
                    request_id=request_id
                )
                audit_output_scan = {
                    "is_blocked": output_scan_result.is_blocked,
                    "decision": output_scan_result.decision,
                    "blocked_by": output_scan_result.blocked_by,
                    "blocked_reason": output_scan_result.blocked_reason,
                    "score": output_scan_result.score,
                }

                if output_scan_result.is_blocked:
                    logger.warning(
                        "Output blocked by firewall",
                        request_id=request_id,
                        blocked_by=output_scan_result.blocked_by,
                        reason=output_scan_result.blocked_reason
                    )

                    metrics.increment_blocked_requests(blocked_by=output_scan_result.blocked_by)

                    # 写入审计日志
                    audit_decision = "BLOCK"
                    audit_blocked_by = output_scan_result.blocked_by
                    audit_blocked_reason = output_scan_result.blocked_reason
                    await write_audit_log(
                        request_id=request_id,
                        user_id=user_id,
                        messages=audit_messages,
                        input_scan_result=audit_input_scan,
                        response=audit_response,
                        output_scan_result=audit_output_scan,
                        decision=audit_decision,
                        blocked_by=audit_blocked_by,
                        blocked_reason=audit_blocked_reason,
                        duration_ms=int((time.time() - start_time) * 1000),
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
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Output scan error: {e}")

        # ==================== 步骤 4: 成功响应 ====================
        duration = time.time() - start_time

        metrics.increment_successful_requests(duration=duration)

        # 写入审计日志
        await write_audit_log(
            request_id=request_id,
            user_id=user_id,
            messages=audit_messages,
            input_scan_result=audit_input_scan,
            response=audit_response,
            output_scan_result=audit_output_scan,
            decision=audit_decision,
            blocked_by=audit_blocked_by,
            blocked_reason=audit_blocked_reason,
            duration_ms=int(duration * 1000),
        )

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

        # 写入错误审计日志
        await write_audit_log(
            request_id=request_id,
            user_id=user_id,
            messages=audit_messages,
            input_scan_result=audit_input_scan,
            response=None,
            output_scan_result=None,
            decision="ERROR",
            blocked_by="InternalError",
            blocked_reason=str(e),
            duration_ms=int((time.time() - start_time) * 1000),
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Internal server error", "request_id": request_id}
        )


# ==================== 输入扫描端点 ====================

@app.post("/api/v1/scan/input")
async def scan_input(
    http_request: Request,
    user: dict = Depends(get_current_user)
):
    """
    仅扫描用户输入，不生成响应

    用于后端快速检测输入是否安全
    """
    request_id = http_request.headers.get(
        "X-Request-ID",
        f"scan-{int(time.time() * 1000)}"
    )

    try:
        # 获取请求体
        body = await http_request.json()
        messages = body.get("messages", [])

        # 执行输入扫描
        result = await firewall_manager.scan_input(
            messages=messages,
            request_id=request_id
        )

        if result.is_blocked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "is_blocked": True,
                    "decision": result.decision,
                    "blocked_by": result.blocked_by,
                    "blocked_reason": result.blocked_reason,
                    "score": result.score
                }
            )

        return ScanResponse(
            is_blocked=False,
            decision=result.decision,
            score=result.score
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Input scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e)}
        )


@app.post("/api/v1/scan/input/batch", response_model=BatchScanResponse)
async def scan_input_batch(
    request: BatchScanRequest,
    user: dict = Depends(get_current_user)
):
    """
    批量扫描用户输入，不生成响应。

    说明：
    - 与 /api/v1/scan/input 共享同一底层 scan_input 逻辑，保证检测口径一致。
    - 仅减少 HTTP 往返与序列化开销，提升大数据集吞吐。
    """
    try:
        max_items = int(os.getenv("BATCH_SCAN_MAX_ITEMS", "200"))
        if len(request.items) == 0:
            return BatchScanResponse(results=[])
        if len(request.items) > max_items:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": f"Too many items in batch. Max allowed: {max_items}"}
            )

        raw_concurrency = int(os.getenv("BATCH_SCAN_CONCURRENCY", "8"))
        concurrency = max(1, min(16, raw_concurrency))
        semaphore = asyncio.Semaphore(concurrency)
        request_base_id = f"batch-{int(time.time() * 1000)}"

        async def _scan_one(index: int, item: ScanRequest) -> BatchScanItemResult:
            async with semaphore:
                result = await firewall_manager.scan_input(
                    messages=item.messages,
                    request_id=f"{request_base_id}-{index}"
                )
                return BatchScanItemResult(
                    index=index,
                    is_blocked=result.is_blocked,
                    decision=result.decision,
                    blocked_by=result.blocked_by,
                    blocked_reason=result.blocked_reason,
                    score=result.score,
                )

        tasks = [_scan_one(i, item) for i, item in enumerate(request.items)]
        results = await asyncio.gather(*tasks)
        results.sort(key=lambda x: x.index)
        return BatchScanResponse(results=results)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch input scan error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": str(e)}
        )


# ==================== 多模态扫描端点 ====================

class MultimodalScanRequest(BaseModel):
    """多模态扫描请求"""
    messages: List[Dict[str, str]] = Field(
        ...,
        description="消息列表"
    )
    imageBase64: Optional[str] = Field(None, description="Base64 encoded image")
    imageUrl: Optional[str] = Field(None, description="Image URL")


class MultimodalScanResponse(BaseModel):
    """多模态扫描响应"""
    is_blocked: bool
    decision: str
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    score: float
    metadata: Optional[Dict[str, Any]] = None


@app.post("/api/v1/scan/multimodal")
async def scan_multimodal(
    request: MultimodalScanRequest,
    http_request: Request,
    user: dict = Depends(get_current_user)
):
    """
    多模态扫描端点（文本 + 图像）

    使用三层策略：
    1. 轻量层：OCR + PromptGuard + 规则（秒级）
    2. 疑似层：MiniMax 多模态重检
    3. 融合决策：加权融合分数

    Args:
        request: 多模态扫描请求（包含消息和图像）
        http_request: HTTP 请求对象
        user: 当前用户信息

    Returns:
        MultimodalScanResponse: 扫描结果
    """
    request_id = http_request.headers.get(
        "X-Request-ID",
        f"mmscan-{int(time.time() * 1000)}"
    )

    try:
        logger.info(
            "Multimodal scan request received",
            request_id=request_id,
            has_image=bool(request.imageBase64 or request.imageUrl)
        )

        # 执行多模态扫描
        result = await firewall_manager.scan_multimodal_input(
            messages=request.messages,
            image_base64=request.imageBase64,
            image_url=request.imageUrl,
            request_id=request_id
        )

        if result.is_blocked:
            logger.warning(
                "Multimodal input blocked",
                request_id=request_id,
                blocked_by=result.blocked_by,
                score=result.score
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "is_blocked": True,
                    "decision": result.decision,
                    "blocked_by": result.blocked_by,
                    "blocked_reason": result.blocked_reason,
                    "score": result.score,
                    "metadata": result.metadata,
                    "request_id": request_id
                }
            )

        logger.info(
            "Multimodal input allowed",
            request_id=request_id,
            score=result.score
        )

        return MultimodalScanResponse(
            is_blocked=False,
            decision=result.decision,
            score=result.score,
            metadata=result.metadata
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Multimodal scan error: {e}", request_id=request_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "Multimodal scan failed", "request_id": request_id}
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

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "18000"))
    log_level = os.getenv("UVICORN_LOG_LEVEL", "info")

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=False,
        log_level=log_level
    )
