from enum import StrEnum
from typing import List, Optional
from pydantic import BaseModel, Field

from app.utils.common import get_js_timestamp


class TokenScopes(StrEnum):
    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"


class AccessTokenInfo(BaseModel):
    value: str
    issued_at: int
    expires_at: int
    scopes: List[TokenScopes]


class RefreshTokenInfo(BaseModel):
    value: str
    issued_at: int
    expires_at: int
    revoked: bool
    client_id: str | None = None


class Session(BaseModel):
    user_id: str
    access_token: AccessTokenInfo
    refresh_token: RefreshTokenInfo
    created_at: int = Field(default_factory=get_js_timestamp)
    last_used_at: int = Field(default_factory=get_js_timestamp)


class TokenType(StrEnum):
    ACCESS = "access_token"
    REFRESH = "refresh_token"
    ID = "id_token"


class TokenData(BaseModel):
    sub: str  # Subject (user ID)
    exp: int  # Expiration time (timestamp milliseconds)
    iat: int  # Issued at (timestamp milliseconds)
    jti: str  # JWT ID
    client_id: Optional[str] = None
    scope: Optional[List[TokenScopes]] = None
    token_type: TokenType


class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None


class TokenIntrospectionRequest(BaseModel):
    token: str
    token_type_hint: Optional[TokenType] = None


class TokenIntrospectionResponse(BaseModel):
    active: bool
    scope: Optional[str] = None
    client_id: Optional[str] = None
    username: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    sub: Optional[str] = None


class TokenRevocationRequest(BaseModel):
    token: str
    token_type_hint: Optional[TokenType] = None
