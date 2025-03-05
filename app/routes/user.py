from fastapi import APIRouter, Depends, HTTPException, status

from app.models.user import User
from app.services.token import TokensSvc
from app.services.user import UsersSvc
from app.utils.security import get_token

router = APIRouter(
    prefix="/user",
    tags=["User"],
    responses={404: {"description": "Not found"}},
    dependencies=[],
)


@router.get("/me", response_model=User)
def get_current_user(
        token_service: TokensSvc,
        user_service: UsersSvc,
        token: str = Depends(get_token)):
    token_data = token_service.validate_token(token)
    is_revoked = token_service.is_token_revoked(token)
    if not token_data or is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    user_dict = user_service.get_user_by_id(token_data.sub)
    if not user_dict:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return User(**user_dict)
