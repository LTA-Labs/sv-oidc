from typing import NamedTuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

from app.utils.common import get_date


class AuthUser(NamedTuple):
    id: str
    vendor_id: str
    session_idp: str | None = None
    session_idp_user_id: str | None = None


class UserBase(BaseModel):
    username: EmailStr
    contact_email: EmailStr


class UserCreate(UserBase):
    zkp_commitment: bytes


class User(UserBase, extra="ignore"):
    user_id: str
    created_at: datetime = Field(default_factory=get_date)
    updated_at: datetime = Field(default_factory=get_date)
    is_blocked: bool = False


class UserInDB(User):
    zkp_commitment: bytes
