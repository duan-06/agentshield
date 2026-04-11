"""
Llama Shield - Pydantic 数据模型
"""

from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime


class Message(BaseModel):
    """消息模型 - 支持纯文本和多模态内容"""
    role: str = Field(..., description="消息角色: user/assistant/system")
    content: str = Field(..., description="消息内容")
    imageBase64: Optional[str] = Field(None, description="Base64 encoded image (PNG/JPEG)")
    imageUrl: Optional[str] = Field(None, description="Image URL for multimodal input")


class ChatRequest(BaseModel):
    """聊天请求模型"""
    messages: List[Message] = Field(
        ...,
        description="消息列表"
    )
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1, le=8192)
    stream: bool = Field(default=False)


class ChatResponse(BaseModel):
    """聊天响应模型"""
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Dict[str, int]


class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str
    version: str
    firewall_status: str
    database_status: str
    uptime: float


class BlockedResponse(BaseModel):
    """请求被阻断时的响应"""
    error: str
    blocked_reason: str
    blocked_by: str
    request_id: str


class StatsResponse(BaseModel):
    """统计信息响应"""
    total_requests: int
    blocked_requests: int
    successful_requests: int
    block_rate: float
    average_latency_ms: float
    requests_per_minute: float


class ScanScore(BaseModel):
    """扫描分数模型"""
    scanner: str
    score: float
    category: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AuditLogEntry(BaseModel):
    """审计日志条目"""
    request_id: str
    user_id: Optional[str] = None
    timestamp: datetime
    messages: List[Message]
    response: Optional[str] = None
    decision: str
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    duration_ms: Optional[int] = None
    input_scan: Optional[Dict[str, Any]] = None
    output_scan: Optional[Dict[str, Any]] = None
