"""
数据库连接管理（MySQL 异步）
使用 aiomysql + SQLAlchemy 2.x 异步引擎
"""

import os
import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.db_models import Base

logger = logging.getLogger(__name__)

# ==================== 连接配置 ====================

def get_mysql_url() -> str:
    """从环境变量构建 MySQL 异步连接 URL"""
    host = os.getenv("MYSQL_HOST", "localhost")
    port = os.getenv("MYSQL_PORT", "3306")
    db = os.getenv("MYSQL_DB", "agentshield")
    user = os.getenv("MYSQL_USER", "root")
    password = os.getenv("MYSQL_PASSWORD", "123456")
    return f"mysql+aiomysql://{user}:{password}@{host}:{port}/{db}?charset=utf8mb4"


_engine = None
_session_factory = None


async def init_db():
    """初始化数据库引擎，创建所有表（如果不存在）"""
    global _engine, _session_factory

    try:
        url = get_mysql_url()
        _engine = create_async_engine(
            url,
            echo=False,
            poolclass=NullPool,
            future=True,
        )
        _session_factory = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # 创建所有表（幂等操作）
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("MySQL database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI 依赖注入：获取异步数据库会话"""
    if _session_factory is None:
        await init_db()
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db():
    """关闭数据库连接池"""
    global _engine
    if _engine:
        await _engine.dispose()
        logger.info("Database connection pool closed")


async def write_audit_log(
    request_id: str,
    user_id: int | None,
    messages: list,
    input_scan_result: dict | None,
    response: str | None,
    output_scan_result: dict | None,
    decision: str,
    blocked_by: str | None,
    blocked_reason: str | None,
    duration_ms: int | None,
    extra_data: dict | None = None,
):
    """
    写入审计日志到数据库

    Args:
        request_id: 请求唯一标识
        user_id: 用户 ID（可能为空）
        messages: 消息列表
        input_scan_result: 输入扫描结果
        response: 模型回复
        output_scan_result: 输出扫描结果
        decision: 决策（ALLOW/BLOCK）
        blocked_by: 阻断来源
        blocked_reason: 阻断原因
        duration_ms: 处理耗时（毫秒）
        extra_data: 额外数据
    """
    from app.db_models import AuditLog

    if _session_factory is None:
        logger.warning("Database not initialized, skipping audit log")
        return

    async with _session_factory() as session:
        try:
            audit_log = AuditLog(
                request_id=request_id,
                user_id=user_id,
                messages=messages,
                input_scan_result=input_scan_result,
                response=response,
                output_scan_result=output_scan_result,
                decision=decision,
                blocked_by=blocked_by,
                blocked_reason=blocked_reason,
                duration_ms=duration_ms,
                extra_data=extra_data,
            )
            session.add(audit_log)
            await session.commit()
            logger.info(f"Audit log written: request_id={request_id}, decision={decision}")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")
            await session.rollback()
