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
