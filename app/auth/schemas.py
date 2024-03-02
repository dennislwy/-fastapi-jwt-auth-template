from pydantic import BaseModel
from datetime import datetime

class TokensResponse(BaseModel):
    """
    A Pydantic model representing the response containing access and refresh tokens.

    Attributes:
        access_token (str): The access token for the user.
        refresh_token (str): The refresh token for the user.
        token_type (str): The type of the token, defaults to "bearer".
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class SessionInfo(BaseModel):
    """
    A Pydantic model representing the information of a user session.

    Attributes:
        user_id (str): The ID of the user.
        session_id (str): The ID of the session.
        user_agent (str): The user agent string of the user's browser.
        user_host (str): The host of the user.
        last_active (datetime): The datetime when the user was last active.
        exp (int): The expiration time of the session in seconds since the epoch.
    """
    user_id: str
    session_id: str
    user_agent: str
    user_host: str
    last_active: datetime
    exp: int
