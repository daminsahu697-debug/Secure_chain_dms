from fastapi import APIRouter
from app.api.v1.endpoints import health, documents, auth, audit_logs, personas

api_router = APIRouter()
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(personas.router)
api_router.include_router(documents.router, prefix="/documents", tags=["Documents"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["Audit"])

