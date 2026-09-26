"""
main.py — SecureChain DMS API Gateway entry point.
Single HTTP server that orchestrates all 3 microservices.

Run: uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.auth import router as auth_router
from routes.cases import router as cases_router
from routes.documents import router as documents_router
from routes.verify import router as verify_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logging.getLogger("uvicorn.access").setLevel(logging.INFO)

app = FastAPI(
    title="SecureChain DMS — API Gateway",
    description=(
        "Zero-Trust Legal Document Management System for SIH26190. "
        "Orchestrates the AI-OCR Pipeline, Quorum Approval Engine, "
        "AES-256 Security Layer, PostgreSQL (Vault 1), and Cloudflare R2 (Vault 2)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow the React frontend (dev: 5173, prod: update with real domain)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount all route groups
app.include_router(auth_router, prefix="/api/v1")
app.include_router(cases_router, prefix="/api/v1")
app.include_router(documents_router, prefix="/api/v1")
app.include_router(verify_router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "UP",
        "service": "SecureChain DMS API Gateway",
        "version": "1.0.0",
        "microservices": {
            "ai_ocr_pipeline":      "http://localhost:8001/api/health",
            "quorum_engine":        "http://localhost:3000/health",
            "vault1_postgresql":    "localhost:5432/securechain_db",
            "vault2_cloudflare_r2": "securechain-vault2.r2.cloudflarestorage.com",
        }
    }
