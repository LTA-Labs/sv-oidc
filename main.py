from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import redis.asyncio as redis
import uvicorn

from app.routes import auth, oidc, user
from app.config import settings
from app.utils.rate_limiter import FastAPILimiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    redis_connection = redis.from_url(
        settings.REDIS_URI, encoding="utf-8", decode_responses=True
    )
    await FastAPILimiter.init(redis_connection)
    yield
    # Clean up
    await FastAPILimiter.close()

app = FastAPI(
    title=settings.APP_NAME,
    # root_path=settings.API_PREFIX,
    description="Secrets Vault OpenID Connect service with image-based Zero-Knowledge Proof authentication",
    version="0.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware)

app.include_router(auth.router)
app.include_router(oidc.router)
app.include_router(user.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
