"""
This module contains the router for authentication-related endpoints.

It includes routes for user registration, user login, user logout, and other authentication-related operations.
"""

import uuid
from typing import Annotated
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import select, exists
from app.users.schemas import UserCreateRequest
from app.database import get_db, AsyncSession
from app.users.models import User
from app.config import settings
from app.auth import session_store
from app.token import token_store
from app.utils import get_current_epoch
from app.token import get_valid_access_token, get_valid_refresh_token
from app.user import get_user_by_id
from .schemas import TokensResponse, SessionInfo
from .utils import authenticate_user, hash_password, create_token

router = r = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

@r.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(request: UserCreateRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    """
    Register a new user.
    \f
    Args:
        request (UserCreateRequest): The user registration request.
        db (AsyncSession): The database session.

    Returns:
        User: The newly created user.

    Raises:
        HTTPException: If the email is already registered.
    """
    # check is user email already registered
    result = await db.execute(select(exists().where(User.email == request.email)))
    user_exists = result.scalar()

    if user_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Email already registered")

    # create new user
    new_user = User(
        email=request.email,
        hashed_password=hash_password(request.password),
        name=request.name
        )

    # save to database
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

# refresh tokens (access and refresh token) using valid refresh token
@r.post("/refresh", response_model=TokensResponse)
async def refresh_tokens(token_payload: Annotated[dict, Depends(get_valid_refresh_token)],
                         db: Annotated[AsyncSession, Depends(get_db)]) -> TokensResponse:

    session_id: str = token_payload.get("sid")
    user_id: str = token_payload.get("sub")
    token_id: str = token_payload.get("jti")

    # get user info by user id
    user = await get_user_by_id(user_id, db)

    # TODO: token TTL should obtain from session cache
    # tokens time-to-live
    access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    # create access token
    access_token = create_token(
        data={"sub": user_id, "email": user.email, "sid": session_id},
        expires_delta=access_token_expires_delta)
    print(f"Created access token: {access_token['token']}, " +
          f"exp: {access_token['payload']['exp']}")

    # create refresh token
    refresh_token = create_token(
        data={"sub": user_id, "sid": session_id},
        expires_delta=refresh_token_expires_delta)
    print(f"Created refresh token: {refresh_token['token']}, " +
          f"exp: {refresh_token['payload']['exp']}")

    # add token IDs to token store
    await _add_tokens_to_store(access_token_id=access_token['payload']['jti'],
                               access_token_ttl=access_token_expires_delta.seconds,
                               refresh_token_id=refresh_token['payload']['jti'],
                               refresh_token_ttl=refresh_token_expires_delta.seconds)

    # revoking old tokens (Prevent token reply attack, refresh token is for single-use only)
    await token_store.remove_with_sibling(token_id)

    # Return the access token, refresh token, and token type
    return TokensResponse(access_token=access_token['token'], refresh_token=refresh_token['token'])

@r.post("/login", response_model=TokensResponse)
async def login(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: Annotated[AsyncSession, Depends(get_db)]) -> TokensResponse:
    """
    Authenticates a user and generates access and refresh tokens.
    \f
    Args:
        request (Request): The incoming request.
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
        db (AsyncSession): The database session.

    Returns:
        TokensResponse: The response containing the access token, refresh token, and token type.

    Raises:
        HTTPException: If the username or password is incorrect, the user is inactive, or the
        user is unverified.
    """
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )

    if not user.is_verified:
        # raise HTTPException(
        #     status_code=status.HTTP_403_FORBIDDEN,
        #     detail="Unverified user"
        # )
        print("DEBUG: Unverified user")

    # generate new session id
    session_id = str(uuid.uuid4())

    access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    # user id string
    user_id = str(user.id)

    # create access token
    access_token = create_token(
        data={"sub": user_id, "email": user.email, "sid": session_id},
        expires_delta=access_token_expires_delta)
    print(f"Created access token: {access_token['token']}, exp: {access_token['payload']['exp']}")

    # create refresh token
    refresh_token = create_token(
        data={"sub": user_id, "sid": session_id},
        expires_delta=refresh_token_expires_delta)
    print(f"Created refresh token: {refresh_token['token']}, exp: {refresh_token['payload']['exp']}")

    # Obtain user browser information
    user_agent = str(request.headers["User-Agent"])
    user_host = request.client.host

    # create new session and add to session store
    await _add_session_to_store(user_id,
                                session_id,
                                user_agent,
                                user_host,
                                refresh_token_expires_delta.seconds)

    # add token IDs to token store
    await _add_tokens_to_store(access_token_id=access_token['payload']['jti'],
                               access_token_ttl=access_token_expires_delta.seconds,
                               refresh_token_id=refresh_token['payload']['jti'],
                               refresh_token_ttl=refresh_token_expires_delta.seconds)

    # Return the access token, refresh token, and token type
    return TokensResponse(access_token=access_token['token'], refresh_token=refresh_token['token'])

@r.post("/logout")
async def logout(token_payload: Annotated[dict, Depends(get_valid_access_token)]):
    """
    Logs out the user
    \f
    User sessions, access & refresh token will be revoked.

    Args:
        token_payload (dict): The access token payload.

    Returns:
        dict: A dictionary containing the message "Successfully logged out".
    """
    user_id: str = token_payload.get("sub")
    session_id: str = token_payload.get("sid")
    token_id: str = token_payload.get("jti")

    # revoke session
    await session_store.remove(user_id, session_id)

    # revoke access & refresh token
    await token_store.remove_with_sibling(token_id)

    return {"message": "Successfully logged out"}

async def _add_tokens_to_store(
    access_token_id: str,
    access_token_ttl: int,
    refresh_token_id: str,
    refresh_token_ttl: int):
    """
    Adds access and refresh tokens to the token store.

    Args:
        access_token_id (str): The ID of the access token.
        access_token_ttl (int): The time-to-live (TTL) of the access token in seconds.
        refresh_token_id (str): The ID of the refresh token.
        refresh_token_ttl (int): The time-to-live (TTL) of the refresh token in seconds.

    Returns:
    None
    """
    print(f"Adding access token '{access_token_id}' to token store")
    await token_store.add(access_token_id, refresh_token_id, access_token_ttl)

    print(f"Adding refresh token '{refresh_token_id}' to token store")
    await token_store.add(refresh_token_id, access_token_id, refresh_token_ttl)

async def _add_session_to_store(
    user_id: str,
    session_id: str,
    user_agent: str,
    user_host: str,
    ttl: int) -> bool:
    """
    Create a new user session and add to the session store.

    Args:
        user_id (str): The user ID.
        session_id (str): The session ID.
        user_agent (str): The user agent.
        user_host (str): The user host.
        ttl (int): The time to live for the session (seconds).

    Returns:
        bool: True if the session was successfully created, False otherwise.
    """
    # add session id to SessionInfo and add to active session cache
    session_info = SessionInfo(user_id=user_id, session_id=session_id, user_agent=user_agent,
                               user_host=user_host, last_active=datetime.utcnow(),
                               exp=get_current_epoch() + ttl)

    # add session id to sessions cache, expiry time = refresh token expiry time
    return await session_store.add(user_id, session_id, session_info, ttl)
