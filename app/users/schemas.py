from pydantic import BaseModel, Field, EmailStr, field_validator
from datetime import datetime

class UserUpdateRequest(BaseModel):
    password: str
    name: str = Field(..., min_length=2, max_length=120)

    # Define a validator for the password field
    @field_validator("password")
    def check_password(cls, value):
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

class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str
    name: str = Field(..., min_length=2, max_length=120)

    # Define a validator for the password field
    @field_validator("password")
    def check_password(cls, value):
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

class UserReadResponse(BaseModel):
    id: str
    email: EmailStr
    name: str
    is_active: bool
    is_superuser: bool
    is_verified: bool
    last_login_at: datetime
    created_at: datetime
    updated_at: datetime

