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
    # SETTINGS CONFIGURATION
    # ========================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()