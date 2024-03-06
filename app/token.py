"""
This module provides functions for token validation.
"""

from typing import Annotated, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from app.auth import session_store
from app.auth import token_store
from .config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

async def get_valid_access_token(
    token: Annotated[str, Depends(oauth2_scheme)]) -> Dict[str, Any]:
    """
    Retrieves and validates the access token.

    Args:
        token (str): The access token to be validated.

    Returns:
        dict: The payload of the access token.

    """
    return await _decode_and_validate_token(token, "access")

async def get_valid_refresh_token(
    token: Annotated[str, Depends(oauth2_scheme)]) -> Dict[str, Any]:
    """
    Retrieves and validates the refresh token.

    Args:
        token (str): The refresh token to be validated.

    Returns:
        dict: The payload of the refresh token.

    """
    return await _decode_and_validate_token(token, "refresh")

async def _decode_and_validate_token(token: str, token_type: str) -> Dict[str, Any]:
    """
    Decode and validate a token, and return the payload if valid.

    Args:
        token (str): The token to decode and validate.
        token_type (str): The type of the token (access or refresh).

    Returns:
        dict: The payload of the token.

    Raises:
        HTTPException: If the token is invalid, expired, or revoked.
    """
    status_code = status.HTTP_401_UNAUTHORIZED

    try:
        # Set the options for the JWT token validation
        options = {
            "require_exp": True,  # expiration time
            "require_sub": True,  # user id
            "require_jti": True,  # token id
            "require_sid": True,  # session id
        }

        if token_type == "access":
            options["require_email"] = True # email

        # Decode, validate JWT token and get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=options)

        if token_type == "refresh" and 'email' in payload:
            raise HTTPException(status_code=status_code,
                                detail="Invalid token type, refresh token was expected")

        # check if the token's session is in active session cache
        user_id: str = payload.get("sub")
        session_id: str = payload.get("sid")

        if not await session_store.exists(user_id=user_id, session_id=session_id):
            raise HTTPException(status_code=status_code, detail="Session was revoked or expired")

        # check if the token is in active token cache
        token_id: str = payload.get("jti")

        if not await token_store.exists(token_id=token_id):
            # for security measures, revoke token's session as well
            print(f"{token_type.capitalize()} token '{token_id}' was revoked or expired, " +
                  f"removing session '{session_id}' as security measure")
            await session_store.remove(user_id=user_id, session_id=session_id)

            raise HTTPException(status_code=status_code,
                                detail=f"{token_type.capitalize()} token was revoked or expired")

        return payload

    except (JWTError, ValidationError) as exc:
        # If there is an error while decoding the token, token is invalid
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
