"""
统计路由 - 图表数据 / 概览统计
对应原 Express /api/stats 路由
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db import get_session
from app.db_models import TestResult, RiskCategory
from app.routes.auth import get_current_user

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/charts")
async def get_charts(
    db: AsyncSession = Depends(get_session),
    user_id: int = Depends(get_current_user),
):
    """获取图表数据：风险等级分布 + 分类测试数量"""

    # 风险等级分布
    risk_rows = await db.execute(
        select(TestResult.riskLevel, func.count(TestResult.id).label("cnt"))
        .where(TestResult.userId == user_id)
        .group_by(TestResult.riskLevel)
    )
    risk_distribution = [
        {"name": row.riskLevel, "value": row.cnt}
        for row in risk_rows.all()
    ]

    # 按类别统计
    cat_rows = await db.execute(
        select(TestResult.categoryId, func.count(TestResult.id).label("cnt"))
        .where(TestResult.userId == user_id)
        .group_by(TestResult.categoryId)
    )
    category_counts = {row.categoryId: row.cnt for row in cat_rows.all()}

    # 查分类名称
    cat_names = await db.execute(select(RiskCategory))
    category_map = {c.id: c.name for c in cat_names.scalars().all()}

    tests_by_category = [
        {"name": category_map.get(cat_id, "Unknown"), "value": cnt}
        for cat_id, cnt in category_counts.items()
    ]

    return {
        "success": True,
        "data": {
            "riskDistribution": risk_distribution,
            "testsByCategory": tests_by_category,
        },
    }


@router.get("/overview")
async def get_overview(
    db: AsyncSession = Depends(get_session),
    user_id: int = Depends(get_current_user),
):
    """获取概览统计：总测试数、危险数、平均分"""

    total = await db.execute(
        select(func.count(TestResult.id)).where(TestResult.userId == user_id)
    )
    total_tests = total.scalar() or 0

    critical = await db.execute(
        select(func.count(TestResult.id)).where(
            TestResult.userId == user_id,
            TestResult.riskLevel == "critical",
        )
    )
    critical_tests = critical.scalar() or 0

    avg = await db.execute(
        select(func.avg(TestResult.riskScore)).where(TestResult.userId == user_id)
    )
    avg_score = float(avg.scalar() or 0.0)

    blocked = await db.execute(
        select(func.count(TestResult.id)).where(
            TestResult.userId == user_id,
            TestResult.isBlocked == True,
        )
    )
    blocked_tests = blocked.scalar() or 0

    return {
        "success": True,
        "data": {
            "totalTests": total_tests,
            "criticalTests": critical_tests,
            "avgRiskScore": round(avg_score, 4),
            "blockedTests": blocked_tests,
        },
    }
