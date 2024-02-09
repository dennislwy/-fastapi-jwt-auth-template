from typing import Annotated
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

    status_code = status.HTTP_401_UNAUTHORIZED

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")

        if user_id is None:
            raise HTTPException(status_code=status_code, detail="Invalid token")

    except (JWTError, ValidationError) as exc:
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc

    user = await get_user_by_id(user_id=user_id, db=db)

    if user:
        status_code = status.HTTP_403_FORBIDDEN
        if active and not user.is_active:
            status_code = status.HTTP_401_UNAUTHORIZED
            raise HTTPException(status_code=status_code, detail="Inactive user")

        if verified and not user.is_verified:
            raise HTTPException(status_code=status_code, detail="Unverified user")

        if superuser and not user.is_superuser:
            raise HTTPException(status_code=status_code, detail="Superuser required")

    else:
        raise HTTPException(status_code=status_code, detail="User not found")

    return user

async def get_user_by_id(user_id: str, db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve a user from the database based on the provided user_id.

    Args:
        db (AsyncSession): The database async session.
        user_id (str, optional): The ID of the user to retrieve. Defaults to None.

    Returns:
        User: The retrieved user object or None if no user is found.
    """
    return await db.get(User, user_id)

async def get_user_by_email(email: str, db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve a user from the database based on the provided email.

    Args:
        db (AsyncSession): The database async session.
        email (str, optional): The email of the user to retrieve. Defaults to None.

    Returns:
        User: The retrieved user object or None if no user is found.
    """
    return await db.execute(select(User).where(User.email == email)).scalar()