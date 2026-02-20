from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Honeypot API"
    API_KEY: str = "honeypot_master_key_2026"
    DEEPSEEK_API_KEY: str = ""
    DEEPSEEK_MODEL: str = "deepseek-chat"

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "ignore"

settings = Settings()
if settings.API_KEY:
    settings.API_KEY = settings.API_KEY.strip()
if settings.DEEPSEEK_API_KEY:
    settings.DEEPSEEK_API_KEY = settings.DEEPSEEK_API_KEY.strip()
if settings.DEEPSEEK_MODEL:
    settings.DEEPSEEK_MODEL = settings.DEEPSEEK_MODEL.strip()
