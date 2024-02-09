import uuid
from datetime import datetime, timedelta
from jose import jwt
from app.config import settings

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
DEFAULT_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

def create_token(data: dict, expires_delta: timedelta) -> str:
    """
    Create a JSON Web Token (JWT) with the given dictionary data and expiration delta.

    Args:
        data (dict): The data to be encoded in the token.
        expires_delta (timedelta): The expiration time delta for the token.

    Returns:
        str: The encoded JWT.

    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=DEFAULT_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"jti": str(uuid.uuid4())})
    to_encode.update({"exp": expire})
    to_encode.update({"iat": datetime.utcnow()})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
