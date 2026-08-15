from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Any


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AIAnalyzeRequest(BaseModel):
    api_key: str
    provider: str = "openai"
    findings: list[dict[str, Any]]