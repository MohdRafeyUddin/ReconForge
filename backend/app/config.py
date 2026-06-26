import os

class Settings:
    PROJECT_NAME: str = "ReconForge"
    API_V1_STR: str = "/api/v1"
    
    # MongoDB Config
    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://127.0.0.1:27017")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "reconforge")
    
    # Security/JWT Config
    SECRET_KEY: str = os.getenv("SECRET_KEY", "reconforge_super_secret_key_change_me_in_prod")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

settings = Settings()
