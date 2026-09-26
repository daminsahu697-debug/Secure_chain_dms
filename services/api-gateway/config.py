"""
config.py — Centralised settings for the API Gateway.
Reads all values from environment variables / .env file.
"""
import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    # --- Database ---
    database_url: str = "postgresql://postgres.buvjudpqfzscxoeqwnay:Securechaindms%40123@aws-0-ap-southeast-1.pooler.supabase.com:5432/postgres"

    # --- JWT ---
    jwt_secret_key: str = "securechain-sih26190-super-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_hours: int = 8
    jwt_refresh_token_expire_days: int = 7

    # --- Downstream Services ---
    ocr_service_url: str = "http://localhost:8001"
    quorum_service_url: str = "http://localhost:3000"

    # --- Cloudflare R2 ---
    r2_account_id: str = "f52686567a73ec8457e8f9e92abcf2b6"
    r2_access_key_id: str = "253456037a929062e8e325862f132243"
    r2_secret_access_key: str = "4785cb2613b8a7ea5badeb6e9accd46322f02cb7a30d14b2a06f61d40e8636bb"
    r2_bucket_name: str = "secure-chain-dms"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
