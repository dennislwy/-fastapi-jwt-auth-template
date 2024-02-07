from fastapi import APIRouter

from app.auth.router import router as auth_router
from app.users.router import router as user_router

router = APIRouter()

router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(user_router, prefix="/users", tags=["Users"])