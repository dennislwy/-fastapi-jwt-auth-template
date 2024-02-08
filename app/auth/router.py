from typing import Annotated
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, exists
from passlib.context import CryptContext
from app.users.schemas import UserCreateRequest
from app.database import get_db, AsyncSession
from app.users.models import User

router = r = APIRouter()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
