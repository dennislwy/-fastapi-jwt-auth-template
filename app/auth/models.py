from sqlalchemy import Column, String, Integer
from app.database import Base

class AuthCache(Base):
    __tablename__ = "auth_cache"

    id = Column(String, primary_key=True, index=True)
    value = Column(String, nullable=True)
    expiration_time = Column(Integer, default=0)
