from typing import Annotated
from fastapi import APIRouter, Depends, status, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPAuthorizationCredentials, HTTPBearer, SecurityScopes
from sqlalchemy import select, exists
from passlib.context import CryptContext
from app.users.schemas import UserCreateRequest
from app.database import get_db, AsyncSession
from app.users.models import User
from app.user import get_user_by_email
from .schemas import TokensResponse

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
    pass

def authenticate_user(email: str, password: str, db: AsyncSession):
    """
    Authenticates a user by checking if the provided username and password match
    the ones stored in the database.

    Args:
        email (str): The email address of the user.
        password (str): The password of the user.
        db (AsyncSession): The database session.

    Returns:
        user: The user object if authentication is successful, False otherwise.
    """
    # Retrieve the user from the database based on the provided username
    user = get_user_by_email(email, db)

    # Check if the user exists
    if not user:
        return False

    # Verify the provided password against the stored password using bcrypt
    if not bcrypt_context.verify(password, user.password):
        return False

    # Return the user object if authentication is successful
    return user