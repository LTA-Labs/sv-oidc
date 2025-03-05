import os
from typing import Annotated, Optional

from fastapi import Depends

from app.config import settings
from app.database import KvDep
from app.utils.encryption import encrypt_data, decrypt_data


class AuthService:
    def __init__(self, db: KvDep):
        self.kv_db = db

    def __call__(self):
        return self

    def generate_challenge(self) -> bytes:
        """
        Generate a random challenge for ZKP authentication.
        """
        # Generate a random challenge
        return os.urandom(settings.ZKP_CHALLENGE_LENGTH)

    async def store_challenge(self, user_id: str, challenge: bytes, timeout: int):
        """
        Store a temporal challenge for a user.
        """
        key_prefix = "challenge:"

        # Encrypt challenge before storing
        encrypted_challenge = encrypt_data(challenge)

        # Store in key-value storage
        await self.kv_db.set_with_expire(key_prefix + user_id, encrypted_challenge, timeout)

    async def get_challenge(self, user_id: str) -> Optional[bytes]:
        """
        Get the stored challenge for a user.
        """
        key_prefix = "challenge:"
        challenge = await self.kv_db.get(key_prefix + user_id)
        if not challenge:
            return None

        # Remove the obtained challenge
        await self.kv_db.delete(key_prefix + user_id)

        # Decrypt challenge
        return decrypt_data(challenge)

    def verify_challenge_response(self, challenge: bytes, response: bytes, commitment: bytes) -> bool:
        """
        Verify a challenge response against a ZKP commitment.

        This is a placeholder function.
        """
        return True


AuthSvc = Annotated[AuthService, Depends(AuthService)]
