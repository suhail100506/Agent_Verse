from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.db.mongo import connect_to_mongo, close_mongo_connection, get_database
from app.templates_library.seed_data import seed_template_library
from app.api.routes import auth, certificates, verification, reports, history

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fake_certificate_verification")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Fake Certificate Verification Service Initializing...")
    await connect_to_mongo()
    db = get_database()
    await seed_template_library(db)
    logger.info("Template library verification & seeding completed.")
    yield
    # Shutdown
    await close_mongo_connection()
    logger.info("Fake Certificate Verification Service Shutting Down...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(certificates.router, prefix=settings.API_V1_STR)
app.include_router(verification.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(history.router, prefix=settings.API_V1_STR)

@app.get(f"{settings.API_V1_STR}/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
