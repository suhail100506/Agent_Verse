import os
try:
    from pydantic_settings import BaseSettings
except ImportError:
    try:
        from pydantic import BaseSettings
    except ImportError:
        from pydantic.v1 import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Fake Certificate Verification"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Database & Cache
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb+srv://mohammedsuhail100506:mongo10@cluster0.zjpg81g.mongodb.net/fake_certificate_verification?retryWrites=true&w=majority")
    MONGO_DB_NAME: str = os.getenv("MONGO_DB_NAME", "fake_certificate_verification")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Authentication
    JWT_SECRET: str = os.getenv("JWT_SECRET", "pramaansetu_hackathon_super_secret_key_2026_change_in_prod")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 # 24 hours
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 7 days
    
    # LLM Reasoning
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # File Storage
    STORAGE_BACKEND: str = os.getenv("STORAGE_BACKEND", "local") # local or cloudinary
    CLOUDINARY_URL: str = os.getenv("CLOUDINARY_URL", "")
    MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "15"))
    
    UPLOAD_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "uploads"))
    REPORT_DIR: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))

    class Config:
        case_sensitive = True

settings = Settings()

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
