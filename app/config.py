import os
from typing import List
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Application settings
    APP_NAME: str = "Secrets Vault OIDC Service"
    API_PREFIX: str = "/api"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"

    # Server environment settings
    SERVER_INSTANCE_NAME: str = os.getenv("SERVER_INSTANCE_NAME", "local")
    ENV_NAME: str = os.getenv("ENV_NAME", "development")
    ENV_VERSION: str = os.getenv("ENV_VERSION", "0.0.1")

    # Log settings
    LOG_FILE_PATH: str = os.getenv("LOG_FILE_PATH", "/var/log/secretsvault/oidc_service.log")
    
    # MongoDB settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "oidc_service")
    
    # JWT settings
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "your-secret-key")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Security settings
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "your-encryption-key")
    
    # ZKP settings
    ZKP_CHALLENGE_LENGTH: int = 32  # Length of challenge in bytes
    ZKP_CHALLENGE_TIMEOUT: int = 5 * 60  # Challenge timeout in seconds

    # Redis Settings
    REDIS_URI: str = os.getenv("REDIS_URI", "redis://127.0.0.1:6379/0")


settings = Settings()
