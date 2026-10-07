from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    app_name: str = 'PHANTOMTRACE'
    database_url: str = 'sqlite:///./phantomtrace.db'
    demo_mode: bool = True
    cors_origins: str = 'http://localhost:3000'
    max_upload_mb: int = 5
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
settings = Settings()
