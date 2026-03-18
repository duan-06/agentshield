"""
认证路由 - 用户注册 / 登录
响应格式与原 Express 后端完全兼容
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from passlib.context import CryptContext
from jose import jwt
from pydantic import BaseModel, EmailStr, field_validator

from app.db import get_session
from app.db_models import User

# ==================== JWT 配置 ====================

JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 7

# ==================== 密码工具 ====================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(user_id: int) -> str:
    expire = datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode(
        {"userId": user_id, "exp": expire},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

# ==================== 认证依赖 ====================

_bearer = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> int:
    """JWT 认证依赖：返回当前用户 ID"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": "No token provided"},
        )
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM]
        )
        user_id: int = payload.get("userId")
        if user_id is None:
            raise ValueError("Missing userId in token")
        return user_id
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": "Invalid token"},
        )

# ==================== Router ====================

router = APIRouter(prefix="/api/auth", tags=["auth"])

# ==================== Pydantic 模型 ====================

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def username_alphanum(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("Username can only contain letters and numbers")
        if len(v) < 3:
            raise ValueError("Username must be at least 3 characters")
        if len(v) > 30:
            raise ValueError("Username must not exceed 30 characters")
        return v

    @field_validator("password")
    @classmethod
    def password_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


# ==================== 路由 ====================

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_session)):
    """用户注册"""
    result = await db.execute(
        select(User).where(
            or_(User.username == body.username, User.email == body.email)
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"success": False, "message": "Username or email already exists"},
        )

    user = User(
        username=body.username,
        email=body.email,
        password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()

    token = create_token(user.id)

    return {
        "success": True,
        "message": "User registered successfully",
        "data": {
            "userId": user.id,
            "username": user.username,
            "email": user.email,
            "token": token,
        },
    }


@router.post("/login")
async def login(body: LoginRequest, db: AsyncSession = Depends(get_session)):
    """用户登录"""
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"success": False, "message": "Invalid credentials"},
        )

    token = create_token(user.id)

    return {
        "success": True,
        "message": "Login successful",
        "data": {
            "userId": user.id,
            "username": user.username,
            "email": user.email,
            "token": token,
        },
    }
