from typing import List
from fastapi import HTTPException, status
from jose import JWTError, jwt
from app.config import settings
from app.auth import session_store

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

async def validate_access_token(token: str):
    """
    Validate the provided access token.

    Args:
        token (str): The access token to be validated.

    Returns:
        dict: The payload of the token.

    Raises:
        HTTPException: If the access token is invalid or the validation fails.
    """
    try:
        # Set the options for the JWT token validation
        options = {
            "require_exp": True, "require_sub": True, "require_jti": True, "require_sid": True
            }

        # Decode the token and validate the payload claims
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=options)

        # token must contains 'email' & 'sid' claims
        _validate_claim(payload, ["email", "sid"])

        # raise exception if session was invalidated (e.g: user logout, password change, account delete)
        await _validate_session_revocation(payload)

        # raise exception if token was invalidated (e.g: old token was reuse after token refreshed)
        # await _validate_token_revocation(payload)

        # update user session last activity timestamp
        await session_store.update_last_activity(payload)

        # return the payload of the token
        return payload

    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=str(exc)) from exc

def _validate_claim(payload: dict, claims: List[str]):
    """
    Validate the claims of the token payload.

    Args:
        payload (dict): The payload of the token.
        claims (List[str]): The list of claims to be validated.

    Raises:
        HTTPException: If the claim is missing in the token.
    """
    for claim in claims:
        if claim in payload:
            continue
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f'missing required key "{claim}" among claims')

async def _validate_session_revocation(payload: dict):
    """
    Validate the session revocation based on the payload.

    Args:
        payload (dict): The payload of the token.

    Raises:
        HTTPException: If the session is revoked or expired.
    """
    user_id = payload.get("sub")
    session_id = payload.get("sid")

    # session considered as revoked or expired if not found in the sessions cache
    if not await session_store.exists(user_id=user_id, session_id=session_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session was revoked or expired")

async def _validate_token_revocation(payload: dict):
    """
    Validate the token revocation based on the payload.

    Args:
        payload (dict): The payload of the token.

    Raises:
        HTTPException: If the token is revoked.
    """
    token_id = payload.get("jti")

    # token considered as revoked if found in the revoked token cache
    if not await revoked_token.exists(token_id=token_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token was revoked")
