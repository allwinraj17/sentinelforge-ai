import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration.

    Values can be supplied through environment variables.
    Local development can use a .env file.
    """

    # ========================================================
    # DATABASE
    # ========================================================

    database_url: str = "sqlite:///./sentinelforge.db"

    # ========================================================
    # CORS
    # ========================================================

    cors_origins: str = "http://localhost:5173"

    # ========================================================
    # ENVIRONMENT
    # ========================================================

    environment: str = "development"

    # ========================================================
    # GROQ AI
    # ========================================================

    groq_api_key: str | None = None

    groq_model: str = "openai/gpt-oss-120b"

    # ========================================================
    # EMAIL / RESEND
    # ========================================================

    resend_api_key: str | None = None

    email_from: str = "onboarding@resend.dev"

    # ========================================================
    # SETTINGS CONFIGURATION
    # ========================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()