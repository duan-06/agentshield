"""
业务数据模型 - 对应 Express/Prisma 的 MySQL 表结构
包含：User、RiskCategory、TestCase、TestResult
以及 LlamaShield 审计日志表（audit_logs）
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean,
    DateTime, JSON, ForeignKey, Index
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


class User(Base):
    """用户表（对应 Prisma users 表）"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    password = Column(String(256), nullable=False)  # bcrypt hash
    createdAt = Column(DateTime, default=datetime.utcnow, nullable=False)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    test_results = relationship("TestResult", back_populates="user", cascade="all, delete")

    __table_args__ = (
        {"mysql_charset": "utf8mb4"},
    )


class RiskCategory(Base):
    """风险类别表（对应 Prisma risk_categories 表）"""
    __tablename__ = "risk_categories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(Text, nullable=False)
    createdAt = Column(DateTime, default=datetime.utcnow, nullable=False)

    test_cases = relationship("TestCase", back_populates="category")
    test_results = relationship("TestResult", back_populates="category")

    __table_args__ = (
        {"mysql_charset": "utf8mb4"},
    )


class TestCase(Base):
    """测试用例表（对应 Prisma test_cases 表）"""
    __tablename__ = "test_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    categoryId = Column(Integer, ForeignKey("risk_categories.id"), nullable=False)
    description = Column(Text, nullable=False)
    examplePrompt = Column(Text, nullable=False)
    createdAt = Column(DateTime, default=datetime.utcnow, nullable=False)

    category = relationship("RiskCategory", back_populates="test_cases")
    test_results = relationship("TestResult", back_populates="test_case")

    __table_args__ = (
        {"mysql_charset": "utf8mb4"},
    )


class TestResult(Base):
    """测试结果表（对应 Prisma test_results 表）"""
    __tablename__ = "test_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    userId = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    categoryId = Column(Integer, ForeignKey("risk_categories.id"), nullable=False)
    testCaseId = Column(Integer, ForeignKey("test_cases.id"), nullable=True)
    input = Column(Text, nullable=False)
    output = Column(Text, nullable=False)
    riskLevel = Column(String(16), nullable=False)   # low/medium/high/critical
    riskScore = Column(Float, default=0.0)
    # 护栏扫描详情
    isBlocked = Column(Boolean, default=False)
    blockedBy = Column(String(32), nullable=True)    # PromptGuard/CodeShield/etc
    blockedReason = Column(String(256), nullable=True)
    scanScore = Column(Float, default=0.0)
    createdAt = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="test_results")
    category = relationship("RiskCategory", back_populates="test_results")
    test_case = relationship("TestCase", back_populates="test_results")

    __table_args__ = (
        Index("idx_user_created", "userId", "createdAt"),
        Index("idx_risk_level", "riskLevel"),
        {"mysql_charset": "utf8mb4"},
    )


class AuditLog(Base):
    """审计日志表（LlamaShield 专用）"""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    messages = Column(JSON, nullable=True)
    input_scan_result = Column(JSON, nullable=True)
    response = Column(Text, nullable=True)
    output_scan_result = Column(JSON, nullable=True)
    decision = Column(String(16), nullable=False)   # ALLOW/BLOCK
    blocked_by = Column(String(32), nullable=True)
    blocked_reason = Column(String(256), nullable=True)
    duration_ms = Column(Integer, nullable=True)
    extra_data = Column(JSON, nullable=True)

    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_decision", "decision"),
        {"mysql_charset": "utf8mb4"},
    )
