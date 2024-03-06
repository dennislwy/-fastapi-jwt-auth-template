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

async def get_token_payload(token: Annotated[str, Depends(oauth2_scheme)]) -> Dict[str, Any]:
    """
    Retrieves the payload from a JWT token and performs validation checks.

    Args:
        token (str): The JWT token to decode and validate.

    Returns:
        dict: The payload of the JWT token.

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
            "require_sid": True  # session id
        }

        # Decode, validate JWT token and get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=options)

        # check if the token's session is in active session cache
        user_id = payload.get("sub")
        session_id = payload.get("sid")

        if not await session_store.exists(user_id=user_id, session_id=session_id):
            raise HTTPException(status_code=status_code,
                                detail="Session was revoked or expired")

        # check if the token is in active token cache
        token_id = payload.get("jti")

        if not await token_store.exists(token_id=token_id):
            # for security measures, revoke token's session as well
            await session_store.remove(user_id=user_id, session_id=session_id)

            raise HTTPException(status_code=status_code,
                                detail="Token was revoked or expired")

        return payload

    except (JWTError, ValidationError) as exc:
        # If there is an error while decoding the token, token is invalid
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
