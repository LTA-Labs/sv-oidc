from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from typing import Optional

from app.config import settings
from app.models.user import UserInDB
from app.models.token import Token, TokenIntrospectionRequest, TokenIntrospectionResponse, TokenRevocationRequest
from app.services.token import TokensSvc
from app.services.user import UsersSvc
from app.services.jwks import JWKSService
from app.utils.security import get_token

router = APIRouter(
    tags=["OIDC"],
    responses={404: {"description": "Not found"}},
    dependencies=[],
)
jwks_service = JWKSService()


@router.get("/.well-known/openid-configuration")
def get_openid_configuration(request: Request):
    """
    Return the OpenID Connect configuration.
    """
    base_url = str(request.base_url).rstrip('/')

    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token",
                                     "code token id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "auth_time", "name", "given_name", "family_name", "email"],
        "introspection_endpoint": f"{base_url}/introspect",
        "revocation_endpoint": f"{base_url}/revoke",
    }


@router.get("/.well-known/jwks.json")
def get_jwks():
    """
    Return the JSON Web Key Set (JWKS) for token verification.
    """
    return jwks_service.get_jwks()


@router.get("/authorize")
def authorize(
        response_type: str,
        client_id: str,
        redirect_uri: str,
        scope: Optional[str] = None,
        state: Optional[str] = None,
        nonce: Optional[str] = None
):
    """
    Handle the initial authentication request.

    This endpoint should redirect to the login page or return an authorization code.
    For this skeleton, we'll just return the parameters.
    """
    return {
        "message": "Authorization endpoint (placeholder)",
        "params": {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "nonce": nonce
        }
    }


@router.post("/token")
def token(
        grant_type: str,
        token_service: TokensSvc,
        user_service: UsersSvc,
        code: Optional[str] = None,
        refresh_token: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        redirect_uri: Optional[str] = None,
):
    """
    Issue access tokens, ID tokens, and refresh tokens.
    """
    if grant_type == "authorization_code":
        # For now, we'll just return a placeholder response
        return Token(
            access_token="placeholder_access_token",
            token_type="bearer",
            expires_in=900,  # 15 minutes in seconds
            refresh_token="placeholder_refresh_token",
            id_token="placeholder_id_token"
        )

    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Refresh token is required"
            )

        # Validate refresh token
        token_data = token_service.validate_token(refresh_token)
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        # Check if token is revoked
        if token_service.is_token_revoked(refresh_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked"
            )

        user_id = token_data.sub
        new_access_token = token_service.create_access_token(user_id)
        new_refresh_token = token_service.create_refresh_token(user_id)

        user_dict = user_service.get_user_by_id(token_data.sub)
        if not user_dict:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        user = UserInDB(**user_dict)
        id_token = token_service.create_id_token(user)

        # Update session
        token_service.update_session(
            refresh_token=refresh_token,
            new_access_token=new_access_token,
            new_refresh_token=new_refresh_token
        )

        return Token(
            access_token=new_access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=new_refresh_token,
            id_token=id_token
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant type: {grant_type}"
        )


@router.get("/userinfo")
def userinfo(token_service: TokensSvc, user_service: UsersSvc, token: str = Depends(get_token)):
    """
    Provide user claims to clients.
    """
    token_data = token_service.validate_token(token)
    if not token_data:
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

    user = UserInDB(**user_dict)

    # Return user claims
    return {
        "sub": user.user_id,
        "email": user.username,
        "email_verified": True,  # Placeholder - this would be based on verification status
    }


@router.post("/introspect")
def introspect(request: TokenIntrospectionRequest, token_service: TokensSvc, user_service: UsersSvc):
    """
    Allow clients to validate and inspect the contents of a token.
    """
    # Validate token
    token_data = token_service.validate_token(request.token)

    # Check if token is revoked
    is_revoked = token_service.is_token_revoked(request.token)

    if not token_data or is_revoked:
        return TokenIntrospectionResponse(active=False)

    user_dict = user_service.get_user_by_id(token_data.sub)
    if not user_dict:
        return TokenIntrospectionResponse(active=False)

    user = UserInDB(**user_dict)

    return TokenIntrospectionResponse(
        active=True,
        scope=" ".join(token_data.scope) if token_data.scope else "",
        client_id=token_data.client_id,
        username=user.username,
        exp=token_data.exp,
        iat=token_data.iat,
        sub=token_data.sub
    )


@router.post("/revoke")
def revoke(request: TokenRevocationRequest, token_service: TokensSvc):
    """
    Allow clients to explicitly revoke a token.
    """
    # Validate token
    token_data = token_service.validate_token(request.token)
    if not token_data:
        # Per RFC 7009, we should return a 200 OK even if the token is invalid
        return Response(status_code=status.HTTP_200_OK)

    # Revoke token
    token_service.revoke_token(request.token)

    return Response(status_code=status.HTTP_200_OK)
