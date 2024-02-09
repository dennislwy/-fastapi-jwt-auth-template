from pydantic import BaseModel
# from datetime import datetime

class TokensResponse(BaseModel):
    access_token: str
    refresh_token: str
