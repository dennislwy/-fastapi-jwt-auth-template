from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DEBUG: bool = False

    DATABASE_URL: str

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_MINUTES: int
    REMEMBER_ME_ACCESS_TOKEN_EXPIRE_MINUTES: int
    REMEMBER_ME_REFRESH_TOKEN_EXPIRE_MINUTES: int

    class Config:
        env_file = './.env'

settings = Settings()