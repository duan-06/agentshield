"""
测试路由 - 风险类别 / 测试评估 / 历史记录
评估接口会调用 LlamaFirewall 对输入进行安全扫描
"""

import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel

from app.db import get_session
from app.db_models import RiskCategory, TestCase, TestResult
from app.routes.auth import get_current_user
from app.firewall import get_firewall_manager

router = APIRouter(prefix="/api/tests", tags=["tests"])


# ==================== Pydantic 模型 ====================

class EvaluateRequest(BaseModel):
    categoryId: int
    input: str
    evaluationCriteria: Optional[str] = None


# ==================== 风险评分工具 ====================

def score_to_risk_level(score: float, is_blocked: bool) -> str:
    """将护栏扫描分数映射到风险等级"""
    if is_blocked:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


# ==================== 路由 ====================

@router.get("/categories")
async def get_categories(db: AsyncSession = Depends(get_session)):
    """获取所有风险类别（含测试用例）"""
    result = await db.execute(
        select(RiskCategory).options(selectinload(RiskCategory.test_cases))
    )
    categories = result.scalars().all()

    return {
        "success": True,
        "data": [
            {
                "id": c.id,
                "name": c.name,
                "description": c.description,
                "createdAt": c.createdAt,
                "testCases": [
                    {
                        "id": tc.id,
                        "description": tc.description,
                        "examplePrompt": tc.examplePrompt,
                    }
                    for tc in c.test_cases
                ],
            }
            for c in categories
        ],
    }


@router.post("/evaluate")
async def evaluate(
    body: EvaluateRequest,
    db: AsyncSession = Depends(get_session),
    user_id: int = Depends(get_current_user),
):
    """
    测试评估 - 核心接口
    使用 LlamaFirewall 对用户输入进行安全扫描，
    并将结果存入数据库。
    """
    # 检查类别是否存在
    cat_result = await db.execute(
        select(RiskCategory).where(RiskCategory.id == body.categoryId)
    )
    category = cat_result.scalar_one_or_none()
    if not category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": "Category not found"},
        )

    # 调用 LlamaFirewall 扫描
    firewall = await get_firewall_manager()
    messages = [{"role": "user", "content": body.input}]
    request_id = f"eval-{int(time.time() * 1000)}-{user_id}"

    scan_result = await firewall.scan_input(
        messages=messages,
        request_id=request_id,
    )

    risk_level = score_to_risk_level(scan_result.score, scan_result.is_blocked)
    output_text = (
        f"[BLOCKED by {scan_result.blocked_by}] {scan_result.blocked_reason}"
        if scan_result.is_blocked
        else "Input passed all security checks."
    )

    # 存入数据库
    test_result = TestResult(
        userId=user_id,
        categoryId=body.categoryId,
        input=body.input,
        output=output_text,
        riskLevel=risk_level,
        riskScore=round(scan_result.score, 4),
        isBlocked=scan_result.is_blocked,
        blockedBy=scan_result.blocked_by,
        blockedReason=scan_result.blocked_reason,
        scanScore=round(scan_result.score, 4),
    )
    db.add(test_result)
    await db.flush()

    return {
        "success": True,
        "message": "Test evaluated successfully",
        "data": {
            "id": test_result.id,
            "userId": test_result.userId,
            "categoryId": test_result.categoryId,
            "input": test_result.input,
            "output": test_result.output,
            "riskLevel": test_result.riskLevel,
            "riskScore": test_result.riskScore,
            "isBlocked": test_result.isBlocked,
            "blockedBy": test_result.blockedBy,
            "blockedReason": test_result.blockedReason,
            "createdAt": test_result.createdAt,
        },
    }


@router.get("/history")
async def get_history(
    db: AsyncSession = Depends(get_session),
    user_id: int = Depends(get_current_user),
):
    """获取当前用户的测试历史"""
    result = await db.execute(
        select(TestResult)
        .options(
            selectinload(TestResult.category),
            selectinload(TestResult.test_case),
        )
        .where(TestResult.userId == user_id)
        .order_by(TestResult.createdAt.desc())
    )
    records = result.scalars().all()

    return {
        "success": True,
        "data": [
            {
                "id": r.id,
                "categoryId": r.categoryId,
                "input": r.input,
                "output": r.output,
                "riskLevel": r.riskLevel,
                "riskScore": r.riskScore,
                "isBlocked": r.isBlocked,
                "blockedBy": r.blockedBy,
                "createdAt": r.createdAt,
                "category": {"id": r.category.id, "name": r.category.name} if r.category else None,
                "testCase": {"id": r.test_case.id, "description": r.test_case.description} if r.test_case else None,
            }
            for r in records
        ],
    }


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_session),
    user_id: int = Depends(get_current_user),
):
    """获取当前用户的测试统计（按风险等级分组）"""
    from sqlalchemy import func

    result = await db.execute(
        select(TestResult.riskLevel, func.count(TestResult.id).label("count"))
        .where(TestResult.userId == user_id)
        .group_by(TestResult.riskLevel)
    )
    rows = result.all()

    return {
        "success": True,
        "data": [
            {"riskLevel": row.riskLevel, "_count": row.count}
            for row in rows
        ],
    }
