import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Boolean
from app.database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email = Column(String(120), unique=True, index=True, nullable=False)
    name = Column(String(50), nullable=False)
    hashed_password = Column(String(128), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False, onupdate=datetime.utcnow)
