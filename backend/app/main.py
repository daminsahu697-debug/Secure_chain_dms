import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.api.router import api_router
from app.core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("securechain_dms")

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS Middleware
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include API Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.on_event("startup")
def on_startup():
    """Ensure all core demo personas (APP001, APP002, APP003, POL-IO-001, etc.) are seeded into DB on startup."""
    try:
        from app.db.session import SessionLocal
        from app.db.seed_demo_users import seed_demo_users
        db = SessionLocal()
        try:
            seed_demo_users(db)
            logger.info("Permanently seeded demo users & approval officers into database.")
        finally:
            db.close()
    except Exception as err:
        logger.warning(f"Demo user startup seeding notice: {err}")


# Basic error handling for database connection / query issues
@app.exception_handler(OperationalError)
async def db_operational_exception_handler(request: Request, exc: OperationalError):
    logger.error(f"Database operational error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": "Database connection error. Please verify PostgreSQL service is running and configured correctly.",
            "error_type": "DatabaseOperationalError",
        },
    )


@app.exception_handler(SQLAlchemyError)
async def db_general_exception_handler(request: Request, exc: SQLAlchemyError):
    logger.error(f"Database error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "A database error occurred while processing your request.",
            "error_type": "SQLAlchemyError",
        },
    )


@app.get("/", tags=["Root"])
def read_root():
    return {
        "service": settings.PROJECT_NAME,
        "version": "0.1.0",
        "documentation": "/docs",
        "health_check": f"{settings.API_V1_STR}/health",
    }
