from pydantic import BaseModel
from datetime import datetime

class TokensResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class SessionInfo(BaseModel):
    user_id: str
    session_id: str
    user_agent: str
    user_host: str
    last_active: datetime
    exp: int
