from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime

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

def validate_password(value):
    """
    Validates the password based on the following criteria:
    - Password must have at least 8 characters
    - Password must have at least one uppercase letter
    - Password must have at least one lowercase letter
    - Password must have at least one digit

    Args:
        value (str): The password to be validated.

    Raises:
        ValueError: If the password does not meet the validation criteria.

    Returns:
        str: The validated password.
    """
    # convert the password to a string if it is not already
    value = str(value)
    # check that the password has at least 8 characters, one uppercase letter, one lowercase letter, and one digit
    if len(value) < 8:
        raise ValueError("Password must have at least 8 characters")
    if not any(c.isupper() for c in value):
        raise ValueError("Password must have at least one uppercase letter")
    if not any(c.islower() for c in value):
        raise ValueError("Password must have at least one lowercase letter")
    if not any(c.isdigit() for c in value):
        raise ValueError("Password must have at least one digit")
    return value