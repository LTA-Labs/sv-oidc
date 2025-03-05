from datetime import timedelta
from typing import Annotated, Optional

from fastapi import Depends
from jose import jwt, JWTError

from app.config import settings
from app.database import CollectionsNames, MongoDep
from app.models.token import (
    AccessTokenInfo, RefreshTokenInfo, Session, TokenData, TokenScopes, TokenType
)
from app.models.user import User
from app.utils.common import cuid_generator, get_date, get_js_timestamp


class TokensService:
    def __init__(self, db: MongoDep) -> None:
        self._db = db
        self._collection = CollectionsNames.SESSIONS

    @staticmethod
    def create_access_token(user_id: str, scopes: list[TokenScopes] = None) -> str:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        expires_at = get_date() + expires_delta

        token_data = TokenData(
            sub=user_id,
            exp=get_js_timestamp(expires_at),
            iat=get_js_timestamp(),
            jti=cuid_generator(),
            scope=scopes or [TokenScopes.OPENID, TokenScopes.PROFILE, TokenScopes.EMAIL],
            token_type=TokenType.ACCESS
        )

        return jwt.encode(
            token_data.model_dump(),
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )

    @staticmethod
    def create_refresh_token(user_id: str, client_id: str = None) -> str:
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        expires_at = get_date() + expires_delta

        token_data = TokenData(
            sub=user_id,
            exp=get_js_timestamp(expires_at),
            iat=get_js_timestamp(),
            jti=cuid_generator(),
            client_id=client_id,
            token_type=TokenType.REFRESH
        )

        return jwt.encode(
            token_data.model_dump(),
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )

    @staticmethod
    def create_id_token(user: User) -> str:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        expires_at = get_date() + expires_delta

        claims = {
            "sub": user.user_id,
            "exp": get_js_timestamp(expires_at),
            "iat": get_js_timestamp(),
            "jti": cuid_generator(),
            "email": user.username,
            "email_verified": True,  # Placeholder
            "token_type": TokenType.ID
        }

        return jwt.encode(
            claims,
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )

    @staticmethod
    def validate_token(token: str) -> Optional[TokenData]:
        try:
            # Decode JWT
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )

            # Convert to TokenData
            token_data = TokenData(
                sub=payload["sub"],
                exp=payload["exp"],
                iat=payload["iat"],
                jti=payload["jti"],
                client_id=payload.get("client_id"),
                scope=payload.get("scope"),
                token_type=payload.get("token_type", TokenType.ACCESS)
            )

            # Check if token has expired
            if token_data.exp < get_js_timestamp():
                return None

            return token_data

        except JWTError:
            return None

    def store_session(self, user_id: str, access_token: str, refresh_token: str) -> str:
        access_token_data = self.validate_token(access_token)
        refresh_token_data = self.validate_token(refresh_token)

        if not access_token_data or not refresh_token_data:
            raise ValueError("Invalid tokens")

        access_token_info = AccessTokenInfo(
            value=access_token,
            issued_at=access_token_data.iat,
            expires_at=access_token_data.exp,
            scopes=access_token_data.scope
        )

        refresh_token_info = RefreshTokenInfo(
            value=refresh_token,
            issued_at=refresh_token_data.iat,
            expires_at=refresh_token_data.exp,
            revoked=False,
            client_id=refresh_token_data.client_id
        )

        session = Session(
            user_id=user_id,
            access_token=access_token_info,
            refresh_token=refresh_token_info
        )

        # session = {
        #     "user_id": user_id,
        #     "access_token": {
        #         "value": access_token,
        #         "issued_at": access_token_data.iat,
        #         "expires_at": access_token_data.exp,
        #         "scopes": access_token_data.scope
        #     },
        #     "refresh_token": {
        #         "value": refresh_token,
        #         "issued_at": refresh_token_data.iat,
        #         "expires_at": refresh_token_data.exp,
        #         "revoked": False,
        #         "client_id": refresh_token_data.client_id
        #     },
        #     "created_at": get_date(),
        #     "last_used_at": get_date()
        # }

        return self._db.insert_one(session.model_dump(), self._collection)

    def update_session(self, refresh_token: str, new_access_token: str, new_refresh_token: str):
        # Find session by refresh token
        session = self._db.find_one(
            {
                "refresh_token.value": refresh_token,
                "refresh_token.revoked": False
            },
            self._collection
        )

        if not session:
            raise ValueError("Session not found or refresh token revoked")

        access_token_data = self.validate_token(new_access_token)
        refresh_token_data = self.validate_token(new_refresh_token)

        if not access_token_data or not refresh_token_data:
            raise ValueError("Invalid tokens")

        self._db.update_one(
            {"_id": session["_id"]},
            {"$set": {"refresh_token.revoked": True}},
            self._collection
        )

        new_session = {
            "user_id": session["user_id"],
            "access_token": {
                "value": new_access_token,
                "issued_at": access_token_data.iat,
                "expires_at": access_token_data.exp,
                "scopes": access_token_data.scope
            },
            "refresh_token": {
                "value": new_refresh_token,
                "issued_at": refresh_token_data.iat,
                "expires_at": refresh_token_data.exp,
                "revoked": False,
                "client_id": refresh_token_data.client_id
            },
            "created_at": get_date(),
            "last_used_at": get_date()
        }

        self._db.insert_one(new_session, self._collection)

    def revoke_token(self, token: str):
        session = self._db.find_one(
            {
                "$or": [
                    {"access_token.value": token},
                    {"refresh_token.value": token}
                ]
            },
            self._collection
        )

        if not session:
            return

        # Determine token type
        if session["access_token"]["value"] == token:
            # Revoke access token by setting expires_at to now
            self._db.update_one(
                {"_id": session["_id"]},
                {"$set": {"access_token.expires_at": get_js_timestamp()}},
                self._collection
            )
        else:
            # Revoke refresh token
            self._db.update_one(
                {"_id": session["_id"]},
                {"$set": {"refresh_token.revoked": True}},
                self._collection
            )

    def revoke_all_sessions(self, user_id: str):
        # Revoke all refresh tokens
        self._db.update_many(
            {"user_id": user_id},
            {
                "$set": {
                    "refresh_token.revoked": True,
                    "access_token.expires_at": get_date()
                }
            },
            self._collection
        )

    def is_token_revoked(self, token: str) -> bool:
        session = self._db.find_one(
            {
                "$or": [
                    {"access_token.value": token},
                    {"refresh_token.value": token}
                ]
            },
            self._collection
        )

        if not session:
            return True

        # Determine token type
        if session["access_token"]["value"] == token:
            # Check if access token has expired
            return session["access_token"]["expires_at"] < get_js_timestamp()
        else:
            # Check if refresh token is revoked
            return session["refresh_token"]["revoked"]


TokensSvc = Annotated[TokensService, Depends()]
