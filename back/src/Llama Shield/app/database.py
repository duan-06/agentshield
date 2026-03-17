"""
数据库模块 - PostgreSQL 审计日志

提供：
- 审计表 schema 定义
- 异步日志写入
- 请求历史查询
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, asdict

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index,
    ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.pool import NullPool

logger = logging.getLogger(__name__)

Base = declarative_base()


# ==================== 数据模型 ====================

class AuditLog(Base):
    """审计日志表"""
    __tablename__ = "audit_logs"

    # 主键
    id = Column(Integer, primary_key=True, autoincrement=True)

    # 请求标识
    request_id = Column(String(64), unique=True, nullable=False, index=True)

    # 用户信息
    user_id = Column(String(64), nullable=True, index=True)

    # 时间戳
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # 请求详情
    messages = Column(JSON, nullable=True)  # 原始消息列表
    input_scan_result = Column(JSON, nullable=True)  # 输入扫描结果

    # 响应详情
    response = Column(Text, nullable=True)
    output_scan_result = Column(JSON, nullable=True)  # 输出扫描结果

    # 决策
    decision = Column(String(16), nullable=False)  # ALLOW/BLOCK
    blocked_by = Column(String(32), nullable=True)  # PromptGuard/LlamaGuard/etc
    blocked_reason = Column(String(256), nullable=True)

    # 性能指标
    duration_ms = Column(Integer, nullable=True)
    input_tokens = Column(Integer, nullable=True)
    output_tokens = Column(Integer, nullable=True)

    # 元数据
    extra_data = Column(JSON, nullable=True)

    # 索引
    __table_args__ = (
        Index('idx_timestamp', 'timestamp'),
        Index('idx_decision', 'decision'),
        Index('idx_blocked_by', 'blocked_by'),
        Index('idx_user_timestamp', 'user_id', 'timestamp'),
    )


class SessionTracking(Base):
    """会话追踪表 - 用于多轮对话"""
    __tablename__ = "session_tracking"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(String(64), nullable=True, index=True)

    # 对话历史
    message_history = Column(JSON, nullable=False)

    # 状态
    turn_count = Column(Integer, default=0)
    last_timestamp = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    # 风险评估
    cumulative_risk_score = Column(String(16), default="0.0")

    __table_args__ = (
        Index('idx_user_active', 'user_id', 'is_active'),
    )


# ==================== 数据库连接 ====================

def get_database_url() -> str:
    """获取数据库连接 URL"""
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db = os.getenv("POSTGRES_DB", "llama_shield")
    user = os.getenv("POSTGRES_USER", "llama_shield")
    password = os.getenv("POSTGRES_PASSWORD", "change-me")

    # 使用异步驱动
    return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{db}"


_engine = None
_async_session = None


async def init_db():
    """初始化数据库连接和表结构（开发模式可跳过）"""
    global _engine, _async_session

    try:
        database_url = get_database_url()

        logger.info("Creating async engine...", host=os.getenv("POSTGRES_HOST"))

        _engine = create_async_engine(
            database_url,
            echo=False,
            poolclass=NullPool,
            future=True
        )

        _async_session = sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        # 创建表
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database connection failed, running in memory mode: {e}")
        _engine = None
        _async_session = None


async def get_session() -> AsyncSession:
    """获取数据库会话"""
    if not _async_session:
        await init_db()
    async with _async_session() as session:
        yield session


# ==================== 审计日志写入 ====================

@dataclass
class ScanResultData:
    """扫描结果数据类"""
    scanner_type: str
    scores: dict
    decision: str
    metadata: Optional[dict] = None


class AuditLogger:
    """
    审计日志记录器

    提供异步日志写入，确保：
    - 所有请求都有记录
    - 阻断请求详细记录阻断原因
    - 完整的审计追踪
    """

    def __init__(self):
        self._session = None

    async def _get_session(self) -> Optional[AsyncSession]:
        """获取数据库会话（数据库不可用时返回 None）"""
        if not _async_session:
            try:
                await init_db()
            except Exception:
                return None
        if _async_session is None:
            return None
        return _async_session()

    async def log_successful_request(
        self,
        request_id: str,
        messages: list,
        response: str,
        input_scan,
        output_scan,
        duration: float,
        user_id: Optional[str] = None
    ):
        """记录成功的请求"""
        session = await self._get_session()

        # 数据库不可用时打印日志
        if session is None:
            logger.info(
                f"[Dev Mode] Request completed: {request_id}",
                decision="ALLOW",
                duration_ms=int(duration * 1000)
            )
            return

        try:
            # 转换扫描结果为字典
            input_scan_dict = None
            if input_scan:
                input_scan_dict = {
                    "is_blocked": input_scan.is_blocked,
                    "decision": input_scan.decision,
                    "blocked_by": input_scan.blocked_by,
                    "blocked_reason": input_scan.blocked_reason,
                    "scores": input_scan.scores,
                    "metadata": input_scan.metadata
                }

            output_scan_dict = None
            if output_scan:
                output_scan_dict = {
                    "is_blocked": output_scan.is_blocked,
                    "decision": output_scan.decision,
                    "blocked_by": output_scan.blocked_by,
                    "blocked_reason": output_scan.blocked_reason,
                    "scores": output_scan.scores,
                    "metadata": output_scan.metadata
                }

            log = AuditLog(
                request_id=request_id,
                user_id=user_id,
                messages=messages,
                input_scan_result=input_scan_dict,
                response=response,
                output_scan_result=output_scan_dict,
                decision="ALLOW",
                duration_ms=int(duration * 1000),
                extra_data={
                    "version": "1.0.0",
                    "scan_versions": {
                        "prompt_guard": "2.0",
                        "llama_guard": "4.0",
                        "codeshield": "latest",
                        "alignment_check": "latest"
                    }
                }
            )

            session.add(log)
            await session.commit()

            logger.debug(
                "Audit log written",
                request_id=request_id,
                decision="ALLOW"
            )

        except Exception as e:
            logger.error(
                "Failed to write audit log",
                request_id=request_id,
                error=str(e)
            )
            await session.rollback()
        finally:
            await session.close()

    async def log_blocked_request(
        self,
        request_id: str,
        messages: list,
        blocked_by: str,
        reason: str,
        scan_result=None,
        response: Optional[str] = None,
        user_id: Optional[str] = None
    ):
        """记录被阻断的请求"""
        session = await self._get_session()

        # 数据库不可用时打印日志
        if session is None:
            logger.info(
                f"[Dev Mode] Request blocked: {request_id}",
                decision="BLOCK",
                blocked_by=blocked_by,
                reason=reason
            )
            return

        try:
            # 转换扫描结果为字典
            scan_result_dict = None
            if scan_result:
                scan_result_dict = {
                    "is_blocked": scan_result.is_blocked,
                    "decision": scan_result.decision,
                    "blocked_by": scan_result.blocked_by,
                    "blocked_reason": scan_result.blocked_reason,
                    "scores": scan_result.scores,
                    "metadata": scan_result.metadata
                }

            log = AuditLog(
                request_id=request_id,
                user_id=user_id,
                messages=messages,
                input_scan_result=scan_result_dict,
                response=response,
                decision="BLOCK",
                blocked_by=blocked_by,
                blocked_reason=reason,
                extra_data={
                    "version": "1.0.0",
                    "block_category": blocked_by
                }
            )

            session.add(log)
            await session.commit()

            logger.warning(
                "Blocked request logged",
                request_id=request_id,
                blocked_by=blocked_by,
                reason=reason
            )

        except Exception as e:
            logger.error(
                "Failed to write blocked request log",
                request_id=request_id,
                error=str(e)
            )
            await session.rollback()
        finally:
            await session.close()

    async def log_session_turn(
        self,
        session_id: str,
        message_history: list,
        turn_count: int,
        risk_score: float,
        user_id: Optional[str] = None
    ):
        """记录会话轮次（用于多轮对话追踪）"""
        session = await self._get_session()

        try:
            # 检查是否已存在
            from sqlalchemy import select
            stmt = select(SessionTracking).where(
                SessionTracking.session_id == session_id
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                # 更新现有会话
                existing.message_history = message_history
                existing.turn_count = turn_count
                existing.cumulative_risk_score = str(risk_score)
                existing.last_timestamp = datetime.utcnow()
            else:
                # 创建新会话
                tracking = SessionTracking(
                    session_id=session_id,
                    user_id=user_id,
                    message_history=message_history,
                    turn_count=turn_count,
                    cumulative_risk_score=str(risk_score)
                )
                session.add(tracking)

            await session.commit()

        except Exception as e:
            logger.error(
                "Failed to log session turn",
                session_id=session_id,
                error=str(e)
            )
            await session.rollback()
        finally:
            await session.close()

    async def close(self):
        """关闭数据库连接"""
        global _engine
        if _engine:
            await _engine.dispose()
            logger.info("Database connection closed")


# ==================== 工具函数 ====================

async def cleanup_old_logs(days: int = 90):
    """清理旧日志（保留指定天数）"""
    from sqlalchemy import delete

    session = await AuditLogger()._get_session()

    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        await session.execute(
            delete(AuditLog).where(AuditLog.timestamp < cutoff_date)
        )
        await session.commit()
        logger.info("Old audit logs cleaned up", days=days)
    except Exception as e:
        logger.error("Failed to cleanup old logs", error=str(e))
    finally:
        await session.close()
