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
from .utils import authenticate_user, hash_password, create_token, generate_session_info_data

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

@r.post("/login", response_model=TokensResponse)
async def login(request: Request,
                form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: Annotated[AsyncSession, Depends(get_db)],
                remember_me: bool = False) -> TokensResponse:
    """
    Authenticates a user and generates access and refresh tokens.
    \f
    Args:
        request (Request): The incoming request.
        form_data (OAuth2PasswordRequestForm): The form data containing the username and password.
        db (AsyncSession): The database session.
        remember_me (bool): Whether to remember the user. Defaults to False.

    Returns:
        TokensResponse: The response containing the access token, refresh token, and token type.

    Raises:
        HTTPException: If the username or password is incorrect, the user is inactive, or the
        user is unverified.
    """
    # authenticate user
    user = await authenticate_user(form_data.username, form_data.password, db)

    # check if user is found
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user"
        )

    # check if user is verified
    # if not user.is_verified and not settings.DEBUG:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Unverified user"
    #     )

    # generate new session id
    session_id = str(uuid.uuid4())

    # user id string
    user_id = str(user.id)

    # generate access & refresh token
    access_token, refresh_token = await _generate_tokens(user_id,
                                                         user.email,
                                                         session_id,
                                                         remember_me)

    # Obtain user browser information
    user_agent = str(request.headers["User-Agent"])
    user_host = request.client.host

    # create new session and add to session store
    await _add_session_to_store(user_id=user_id,
                                session_id=session_id,
                                remember_me=remember_me,
                                user_agent=user_agent,
                                user_host=user_host,
                                ttl=int(refresh_token['expires_delta'].total_seconds()))

    # add token IDs to token store
    await _add_tokens_to_store(access_token_id=access_token['payload']['jti'],
                               access_token_ttl=int(access_token['expires_delta']
                                                    .total_seconds()),
                               refresh_token_id=refresh_token['payload']['jti'],
                               refresh_token_ttl=int(refresh_token['expires_delta']
                                                     .total_seconds()))

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


@r.post("/refresh", response_model=TokensResponse)
async def refresh_tokens(request: Request,
                         token_payload: Annotated[dict, Depends(get_valid_refresh_token)],
                         db: Annotated[AsyncSession, Depends(get_db)]) -> TokensResponse:
    """
    Refresh the access and refresh tokens.
    \f
    This function takes a valid refresh token, validates it, and generates a new set of access and refresh tokens.
    It also updates the session information and revokes the old tokens to prevent token replay attacks.

    Args:
        request (Request): The incoming request.
        token_payload (dict): The payload of the valid refresh token.
        db (AsyncSession): The database session.

    Returns:
        TokensResponse: The response containing the new access token, refresh token, and token type.

    Raises:
        HTTPException: If the session or user is not found.
    """
    # Extract the session id, user id, and token id from the token payload
    session_id: str = token_payload.get("sid")
    user_id: str = token_payload.get("sub")
    token_id: str = token_payload.get("jti")

    # Retrieve the session information by session id
    session_info: SessionInfo = await session_store.retrieve(user_id, session_id)
    if session_info is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session not found")

    # Retrieve the user information by user id
    user = await get_user_by_id(user_id, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Generate new access and refresh tokens
    access_token, refresh_token = await _generate_tokens(user_id,
                                                         user.email,
                                                         session_id,
                                                         session_info.remember_me)

    # Update the session information (user_agent, user_host, last_active, exp) and extend its expiry time
    new_session_info_data = generate_session_info_data(request)
    new_session_info_data['exp'] = get_current_epoch() + int(refresh_token['expires_delta']
                                                             .total_seconds())
    # update session info in session store and extend expiry time
    if await session_store.update(user_id, session_id,
                                  data=new_session_info_data,
                                  ttl=int(refresh_token['expires_delta'].total_seconds())):
        print(f"Session info '{session_id}' updated")

    # Add the new token ids to the token store
    await _add_tokens_to_store(access_token_id=access_token['payload']['jti'],
                               access_token_ttl=int(access_token['expires_delta']
                                                    .total_seconds()),
                               refresh_token_id=refresh_token['payload']['jti'],
                               refresh_token_ttl=int(refresh_token['expires_delta']
                                                     .total_seconds()))

    # Revoke the old tokens to prevent token replay attacks (refresh token is for single-use only)
    await token_store.remove_with_sibling(token_id)

    # Return the new access token, refresh token, and token type
    return TokensResponse(access_token=access_token['token'], refresh_token=refresh_token['token'])

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
    remember_me: bool,
    user_agent: str,
    user_host: str,
    ttl: int) -> bool:
    """
    Create a new user session and add to the session store.

    Args:
        user_id (str): The user ID.
        session_id (str): The session ID.
        remember_me (bool): Whether to remember the user
        user_agent (str): The user agent.
        user_host (str): The user host.
        ttl (int): The time to live for the session (seconds).

    Returns:
        bool: True if the session was successfully created, False otherwise.
    """
    # add session id to SessionInfo and add to active session cache
    session_info = SessionInfo(user_id=user_id, session_id=session_id, remember_me=remember_me,
                               user_agent=user_agent, user_host=user_host,
                               last_active=datetime.utcnow(),
                               exp=get_current_epoch() + ttl)

    # add session id to sessions cache, expiry time = refresh token expiry time
    return await session_store.add(user_id, session_id, session_info, ttl)

async def _generate_tokens(user_id: str, email: str, session_id: str, remember_me: bool):
    if not remember_me:
        print("Generating short-lived tokens")
        access_token_exp_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_exp_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    else:
        print("Generating long-lived tokens")
        access_token_exp_delta = timedelta(minutes=settings
                                           .REMEMBER_ME_ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_exp_delta = timedelta(minutes=settings
                                            .REMEMBER_ME_REFRESH_TOKEN_EXPIRE_MINUTES)

    # create access token
    access_token = create_token(
        data={"sub": user_id, "email": email, "sid": session_id},
        expires_delta=access_token_exp_delta)
    print(f"Created access token: {access_token['token']}, exp: {access_token['payload']['exp']}")

    # create refresh token
    refresh_token = create_token(
        data={"sub": user_id, "sid": session_id},
        expires_delta=refresh_token_exp_delta)
    print(f"Created refresh token: {refresh_token['token']}, exp: {refresh_token['payload']['exp']}")

    return access_token, refresh_token
