import uuid
from typing import Annotated
from datetime import timedelta
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from sqlalchemy import select, exists
from passlib.context import CryptContext
from app.users.schemas import UserCreateRequest
from app.database import get_db, AsyncSession
from app.users.models import User
from app.user import get_user_by_email
from app.config import settings
from .schemas import TokensResponse
from .utils import create_token


router = r = APIRouter()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

@r.post("/register", status_code=status.HTTP_201_CREATED)
async def create_user(request: UserCreateRequest, db: Annotated[AsyncSession, Depends(get_db)]):
    # check is user email already registered
    result = await db.execute(select(exists().where(User.email == request.email)))
    user_exists = result.scalar()

    if user_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Email already registered")

    # create new user
    new_user = User(
        email=request.email,
        hashed_password=bcrypt_context.hash(request.password),
        name=request.name
        )

    # save to database
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@r.post("/login", response_model=TokensResponse)
async def login(request: Request, form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                db: Annotated[AsyncSession, Depends(get_db)]):

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

    # if not user.is_verified:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Unverified user"
    #     )

    # generate new session id
    session_id = str(uuid.uuid4())

    access_token_expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires_delta = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)

    # create access token
    access_token = create_token(
        data={"sub": str(user.id), "email": user.email, "sid": session_id},
        expires_delta=access_token_expires_delta)
    print(f"access_token: {access_token}")

    # create refresh token
    refresh_token = create_token(
        data={"sub": str(user.id), "sid": session_id},
        expires_delta=refresh_token_expires_delta)
    print(f"refresh_token: {refresh_token}")

    # Return the access token, refresh token, and token type
    return TokensResponse(access_token=access_token, refresh_token=refresh_token)

async def authenticate_user(email: str, password: str, db: AsyncSession):
    """
    Authenticates a user based on the provided email and password.

    Args:
        email (str): The email of the user.
        password (str): The password of the user.
        db (AsyncSession): The database session.

    Returns:
        Union[User, bool]: The authenticated user object if authentication is successful, False otherwise.
    """
    # Retrieve the user from the database based on the provided username
    user = await get_user_by_email(email, db)

    # Check if the user exists
    if not user:
        return False

    # Verify the provided password against the stored password using bcrypt
    if not bcrypt_context.verify(password, user.hashed_password):
        return False

    # Return the user object if authentication is successful
    return user
