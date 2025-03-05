from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from redis.asyncio import Redis
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError, TimeoutError
from redis.retry import Retry

from ..config import settings


class KvService:
    def __init__(self, redis_uri: str):
        retry_kwargs = {
            "retry_on_error": [ConnectionError, TimeoutError],
            "retry_on_timeout": True,
            "retry": Retry(
                ExponentialBackoff(base=2, cap=16), 3
            ),  # 3 retries with exponential backoff
        }

        self.client = Redis.from_url(redis_uri, **retry_kwargs)

    def __call__(self) -> KvService:
        return self

    async def set(self, key: str, value: str):
        await self.client.set(key, value)

    async def get(self, key: str):
        return await self.client.get(key)

    async def delete(self, key: str):
        return await self.client.delete(key)

    async def exists(self, key: str):
        return await self.client.exists(key)

    async def set_with_expire(self, key: str, value: str, expire: int):
        return await self.client.set(key, value, ex=expire)


KV_STORE = KvService(redis_uri=settings.REDIS_URI)

KvDep = Annotated[KvService, Depends(KV_STORE)]

__all__ = [
    "KvDep",
    "KvService",
    "KV_STORE",
]
