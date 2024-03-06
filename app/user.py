from typing import Annotated
from uuid import UUID
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy import select
from app.users.models import User
from app.database import get_db, AsyncSession
from .config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM

async def current_user(token: Annotated[str, Depends(oauth2_scheme)],
                          db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve the current user based on the provided token.

    Args:
        token (str): The token to use to retrieve the user.
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object.
    """
    return await get_current_user(token, db)

async def current_active_user(token: Annotated[str, Depends(oauth2_scheme)],
                              db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve the current active user based on the provided token.

    Args:
        token (str): The token to use to retrieve the user.
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object.
    """
    return await get_current_user(token, db, active=True)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)],
                           db: Annotated[AsyncSession, Depends(get_db)],
                           active: bool = False,
                           verified: bool = False,
                           superuser: bool = False) -> User:
    """
    Retrieve the current user based on the provided JWT token.

    This function decodes the JWT token to get the user_id and then retrieves the user from the
    database. It also checks if the user is active, verified, and a superuser based on the provided
    parameters.

    Args:
        token (str): The JWT token of the user.
        db (AsyncSession): The database async session.
        active (bool, optional): Whether the user needs to be active. Defaults to False.
        verified (bool, optional): Whether the user needs to be verified. Defaults to False.
        superuser (bool, optional): Whether the user needs to be a superuser. Defaults to False.

    Returns:
        User: The retrieved user object.

    Raises:
        HTTPException: If the token is invalid, the user is not found, the user is inactive, the
        user is unverified, or the user is not a superuser.
    """
    status_code = status.HTTP_401_UNAUTHORIZED

    try:
        # Set the options for the JWT token validation
        options = {"require_exp": True, "require_sub": True, "require_jti": True}

        # Decode, validate JWT token and get the payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options=options)

        # Get the user_id from the payload
        user_id: str = payload.get("sub")

        # If the user_id is None, the token is invalid
        if user_id is None:
            raise HTTPException(status_code=status_code, detail="Invalid token")

    except (JWTError, ValidationError) as exc:
        # If there is an error while decoding the token, it is invalid
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    # Retrieve the user from the database
    user = await get_user_by_id(user_id=user_id, db=db)

    if user:
        status_code = status.HTTP_403_FORBIDDEN
        # If the user needs to be active and is not, raise an exception
        if active and not user.is_active:
            status_code = status.HTTP_401_UNAUTHORIZED
            raise HTTPException(status_code=status_code, detail="Inactive user")

        # If the user needs to be verified and is not, raise an exception
        if verified and not user.is_verified:
            raise HTTPException(status_code=status_code, detail="Unverified user")

        # If the user needs to be a superuser and is not, raise an exception
        if superuser and not user.is_superuser:
            raise HTTPException(status_code=status_code, detail="Superuser required")

    else:
        # If the user is not found in the database, raise an exception
        raise HTTPException(status_code=status_code, detail="User not found")

    return user

async def get_user_by_id(user_id: str, db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve a user from the database based on the provided user_id.

    Args:
        user_id (str): The ID of the user to retrieve.
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object or None if no user is found.
    """
    return await db.get(User, UUID(user_id))

async def get_user_by_email(email: str, db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve a user from the database based on the provided email.

    Args:
        email (str, optional): The email of the user to retrieve
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object or None if no user is found.
    """
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar()
