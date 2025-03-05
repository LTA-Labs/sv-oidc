import random
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwk
from jose.backends.base import Key

from app.crytography import Cipher, Signer
from app.logs import oidc_logger
_get_bearer_token = HTTPBearer(auto_error=False)

__key: dict[str, Key] = {}

__cipher: Cipher | None = None

__signer: Signer | None = None


def load_cipher_keys(public_key: bytes, private_key: bytes, password: bytes) -> None:
    global __cipher
    __cipher = Cipher(public_key, private_key, password)


def load_sign_keys(public_key: bytes, private_key: bytes, password: bytes) -> None:
    global __signer
    __signer = Signer(public_key, private_key, password)


def set_sing_key(keys_config: list[dict]) -> None:
    global __key
    keys: dict[str, Key] = {}

    for key in keys_config:
        try:
            jwk_key = jwk.construct(key)
        except Exception as e:
            oidc_logger.warning("Unable to construct key: %s", e)
            continue
        kid = key.get("kid", str(random.getrandbits(32)))
        keys[kid] = jwk_key

    __key = keys


def get_cipher() -> Cipher:
    if __cipher is None:
        raise ValueError("Cipher keys not loaded.")
    return __cipher


def get_signer() -> Signer:
    if __signer is None:
        raise ValueError("Signer keys not loaded.")
    return __signer


CipherDep = Annotated[Cipher, Depends(get_cipher)]
SignerDep = Annotated[Signer, Depends(get_signer)]


async def get_token(
    auth: Annotated[Optional[HTTPAuthorizationCredentials], Depends(_get_bearer_token)],
) -> str:
    token = auth.credentials if auth is not None else None

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing or unknown",
        )

    return token
