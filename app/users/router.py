from typing import Annotated
from fastapi import APIRouter, Depends
from .models import User
from app.user import current_active_user, current_user

router = r = APIRouter()

@r.get("/me")
async def authenticated_route(user: Annotated[User, Depends(current_user)]):
    return {"message": f"Hello {user.name} <{user.email}>"}
