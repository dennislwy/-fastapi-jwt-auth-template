from typing import Annotated
from uuid import UUID
from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from app.users.models import User
from app.database import get_db, AsyncSession
from app.token import get_valid_access_token

async def current_user(token_payload: Annotated[dict, Depends(get_valid_access_token)],
                       db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve the current user based on the provided token.

    Args:
        token_payload (dict): The token payload to use to retrieve the user.
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object.
    """
    return await get_current_user(token_payload, db)

async def current_active_user(token_payload: Annotated[dict, Depends(get_valid_access_token)],
                              db: Annotated[AsyncSession, Depends(get_db)]) -> User:
    """
    Retrieve the current active user based on the provided token.

    Args:
        token_payload (dict): The token payload to use to retrieve the user.
        db (AsyncSession): The database async session.

    Returns:
        User: The retrieved user object.
    """
    return await get_current_user(token_payload, db, active=True)

async def get_current_user(token_payload: Annotated[dict, Depends(get_valid_access_token)],
                           db: Annotated[AsyncSession, Depends(get_db)],
                           active: bool = False,
                           verified: bool = False,
                           superuser: bool = False) -> User:
    """
    Retrieve the current user based on the provided token payload.

    Args:
        token_payload (dict): The payload of the JWT token.
        db (AsyncSession): The database session.
        active (bool, optional): Filter users by active status. Defaults to False.
        verified (bool, optional): Filter users by verified status. Defaults to False.
        superuser (bool, optional): Filter users by superuser status. Defaults to False.

    Returns:
        User: The current user.

    Raises:
        HTTPException: If the token is invalid or there is an error while decoding it.
    """
    status_code = status.HTTP_401_UNAUTHORIZED

    # Get the user_id from the payload
    user_id: str = token_payload.get("sub")

    # If the user_id is None, the token is invalid
    if user_id is None:
        raise HTTPException(status_code=status_code, detail="Invalid token")

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
