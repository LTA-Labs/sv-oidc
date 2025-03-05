import datetime
from typing import Callable, Optional

from cuid2 import cuid_wrapper
from fastapi import Request

from app.config import settings

TOKEN_ISSUER = f"secrets-vault-{settings.ENV_NAME.lower()}"
_TOKEN_EXPIRATION_TIME = 30 * 60  # 30 minutes

cuid_generator: Callable[[], str] = cuid_wrapper()


def get_date() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def get_js_timestamp(dt: datetime.datetime | None = None) -> int:
    if dt:
        return int(dt.timestamp() * 1000)
    return int(get_date().timestamp() * 1000)


def get_client_ip(request: Request | None) -> str:
    if request is None:
        return "UNKNOWN IP"

    ip = request.headers.get("CF-Connecting-IP")

    if ip:
        return ip

    ip = request.headers.get("X-Forwarded-For")

    if ip:
        ip = ip.split(",")[0]
        return ip

    # Fallback to the X-Real-IP header if the X-Forwarded-For header is not present or UKNOWN if both are missing
    ip = request.headers.get("X-Real-IP", None)

    if ip is None and request.client is not None:
        ip = request.client.host
    else:
        ip = "UNKNOWN IP"

    return ip
