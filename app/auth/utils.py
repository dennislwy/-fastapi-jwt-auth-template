import uuid
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
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


def create_token(data: dict, expires_delta: timedelta) -> dict:
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

    # If an expiration delta is provided, calculate the expiration time by adding it to the current time
    if expires_delta:
        expire = datetime.utcnow() + expires_delta

    # If no expiration delta is provided, use the default token expiration time
    else:
        expire = datetime.utcnow() + timedelta(minutes=DEFAULT_TOKEN_EXPIRE_MINUTES)

    # Add a unique identifier to the token data
    to_encode.update({"jti": str(uuid.uuid4())})
    # Add the expiration time to the token data
    to_encode.update({"exp": expire})
    # Add the issued at time to the token data
    to_encode.update({"iat": datetime.utcnow()})

    return {
        'token': jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM),
        'payload': to_encode
        }