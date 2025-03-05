from base64 import b64encode
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import settings
from app.models.auth import RegisterRequest, AuthRequest, AuthResponse, AuthChallenge
from app.models.user import UserInDB
from app.services.auth import AuthSvc
from app.services.user import UsersSvc
from app.services.token import TokensSvc
from app.utils.common import get_date, get_js_timestamp
from app.utils.rate_limiter import RateLimiter
from app.utils.security import get_token

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
    responses={404: {"description": "Not found"}},
    dependencies=[],
)


@router.post(
    "/register",
    dependencies=[Depends(RateLimiter(times=20, seconds=1))],
    status_code=status.HTTP_201_CREATED,
)
def register(request: RegisterRequest, user_service: UsersSvc):
    # Check if user already exists
    if user_service.get_user_by_username(request.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered"
        )

    user_id = user_service.create_user(
        username=request.username,
        contact_email=request.contact_email,
        zkp_commitment=request.zkp_commitment
    )

    return {"user_id": user_id}


@router.post(
    "/challenge",
    dependencies=[Depends(RateLimiter(times=1, seconds=2))]
)
async def get_challenge(username: str, user_service: UsersSvc, auth_service: AuthSvc):
    user_dict = user_service.get_user_by_username(username)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user = UserInDB(**user_dict)

    challenge = auth_service.generate_challenge()
    expires_at = get_date() + timedelta(seconds=settings.ZKP_CHALLENGE_TIMEOUT)
    expires_at = get_js_timestamp(expires_at)

    await auth_service.store_challenge(user.user_id, challenge, settings.ZKP_CHALLENGE_TIMEOUT)

    # Convert to string so it can be json-serializable
    # In frontend it could be decoded back to bytes
    challenge_b64 = b64encode(challenge).decode('ascii')

    return AuthChallenge(challenge=challenge_b64, expires_at=expires_at)


@router.post(
    "/authenticate",
    dependencies=[Depends(RateLimiter(times=20, seconds=1))],
)
async def authenticate(
        request: AuthRequest,
        user_service: UsersSvc,
        auth_service: AuthSvc,
        token_service: TokensSvc
):
    """
    Authenticate a user using their challenge response.

    The challenge response is computed from the user's image on the client side.
    """
    user_dict = user_service.get_user_by_username(request.username)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user = UserInDB(**user_dict)

    challenge = await auth_service.get_challenge(user.user_id)
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active challenge found. Please request a new challenge."
        )

    if not auth_service.verify_challenge_response(
            challenge=challenge,
            response=request.challenge_response,
            commitment=user.zkp_commitment
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

    access_token = token_service.create_access_token(user.user_id)
    refresh_token = token_service.create_refresh_token(user.user_id)
    id_token = token_service.create_id_token(user)

    token_service.store_session(
        user_id=user.user_id,
        access_token=access_token,
        refresh_token=refresh_token
    )

    return AuthResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES*60,
        refresh_token=refresh_token,
        id_token=id_token
    )


@router.post(
    "/logout",
    dependencies=[Depends(RateLimiter(times=20, seconds=1))],
)
def logout(token_service: TokensSvc, token: str = Depends(get_token)):
    # Validate token
    token_data = token_service.validate_token(token)
    is_revoked = token_service.is_token_revoked(token)
    if not token_data or is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    # Revoke all user sessions
    token_service.revoke_all_sessions(token_data.sub)

    return {"message": "Logged out successfully"}
