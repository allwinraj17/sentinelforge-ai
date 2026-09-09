from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """
    SentinelForge AI application configuration.

    Secrets are loaded from environment variables.
    Local development may use a .env file.

    IMPORTANT:
    Never put real API keys directly in source code.
    """

    # ============================================================
    # APPLICATION
    # ============================================================

    environment: str = "development"

    # ============================================================
    # DATABASE
    # ============================================================

    database_url: str = "sqlite:///./sentinelforge.db"

    # ============================================================
    # CORS
    # ============================================================

    cors_origins: str = (
        "http://localhost:5173,"
        "http://localhost:3000,"
        "https://sentinelforge-ai.vercel.app"
    )

    # ============================================================
    # GROQ AI
    # ============================================================

    groq_api_key: str | None = None

    groq_model: str = (
        "llama-3.3-70b-versatile"
    )

    # ============================================================
    # EMAIL
    # ============================================================

    # Optional backend email configuration.
    #
    # Phase 4 frontend email delivery uses EmailJS.
    # These values are kept optional so the backend can run
    # without requiring a mail provider.

    resend_api_key: str | None = None

    email_from: str = (
        "onboarding@resend.dev"
    )

    # ============================================================
    # SETTINGS CONFIGURATION
    # ============================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()