from typing import Optional
from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    username: EmailStr
    contact_email: EmailStr
    zkp_commitment: bytes


class AuthRequest(BaseModel):
    username: EmailStr
    challenge_response: bytes


class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    id_token: Optional[str] = None


class AuthChallenge(BaseModel):
    challenge: bytes
    expires_at: int  # Unix timestamp


class UnauthorizedMessage(BaseModel):
    detail: str = "Bearer token missing or unknown"


class ExchangeTokenBody(BaseModel):
    token: str


class TokenResponse(BaseModel):
    token: str
