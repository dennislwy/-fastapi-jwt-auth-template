import uuid
from typing import Optional
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from fastapi import Request
from app.config import settings
from app.database import AsyncSession
from app.user import get_user_by_email

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
DEFAULT_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """
    Hashes the provided password using bcrypt.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    return bcrypt_context.hash(password)

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


def create_token(data: dict, expires_delta: Optional[timedelta] = None) -> dict:
    """
    Create a JSON Web Token (JWT) with the given dictionary data and expiration delta.

    Args:
        data (dict): The data to be encoded in the token.
        expires_delta (timedelta): The expiration time delta for the token.

    Returns:
        dict: The token and its payload.
    """
    # Copy the input data to avoid modifying the original dictionary
    to_encode = data.copy()

    # If no expiration delta is provided, use the default token expiration time
    if expires_delta is None:
        expires_delta = timedelta(minutes=DEFAULT_TOKEN_EXPIRE_MINUTES)

    # Calculate the expiration time based on the current time and the expiration delta
    expire = datetime.utcnow() + expires_delta

    # Add a unique identifier to the token data
    to_encode.update({"jti": str(uuid.uuid4())})
    # Add the expiration time to the token data
    to_encode.update({"exp": expire})
    # Add the issued at time to the token data
    to_encode.update({"iat": datetime.utcnow()})

    return {
        'token': jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM),
        'payload': to_encode,
        'expires_delta': expires_delta
        }

def generate_session_info_data(request: Request) -> dict:
    """
    Generate session information data based on the given request.

    Args:
        request (Request): The request object containing the necessary information.

    Returns:
        dict: A dictionary containing the generated session information data.
            - user_agent (str): The user agent from the request headers.
            - user_host (str): The host of the client making the request.
            - last_active (datetime): The current UTC datetime.
    """
    user_agent = request.headers.get("user-agent")
    user_host = request.client.host
    last_active = datetime.utcnow()
    return {"user_agent": user_agent, "user_host": user_host, "last_active": last_active}
