"""Configuration settings for Security Scanner Platform"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Application
    app_name: str = "Security Scanner Platform"
    app_version: str = "1.0.0"
    debug: bool = False
    secret_key: str = "change-me-in-production"
    
    # Database
    database_url: str = "sqlite:///./security_scanner.db"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    
    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 60
    
    # Scan Settings
    max_concurrent_scans: int = 5
    scan_timeout: int = 30
    user_agent: str = "SecurityScanner/1.0"
    
    # Security
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:8000"]
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Notifications
    email_enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""


settings = Settings()
