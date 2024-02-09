from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime
from .utils import validate_password

class UserUpdateRequest(BaseModel):
    """
    Represents a request to update a user's information.

    Attributes:
        password (str): The user's password.
        name (str): The user's name.

    Raises:
        ValueError: If the password does not meet the required criteria.

    """
    password: str
    name: str = Field(..., min_length=2, max_length=120)

    # Define a validator for the password field
    @field_validator("password")
    def check_password(cls, value):
        return validate_password(value)

class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str
    name: str = Field(..., min_length=2, max_length=120)

    # Define a validator for the password field
    @field_validator("password")
    def check_password(cls, value):
        return validate_password(value)

class UserReadResponse(BaseModel):
    """
    Represents the response schema for reading user data.

    Attributes:
        id (str): The user's ID.
        email (EmailStr): The user's email address.
        name (str): The user's name.
        is_active (bool): Indicates if the user is active.
        is_superuser (bool): Indicates if the user is a superuser.
        is_verified (bool): Indicates if the user is verified.
        last_login_at (datetime): The timestamp of the user's last login.
        created_at (datetime): The timestamp of when the user was created.
        updated_at (datetime): The timestamp of when the user information was last updated.
    """
    id: str
    email: EmailStr
    name: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    last_login_at: datetime
    created_at: datetime
    updated_at: datetime
