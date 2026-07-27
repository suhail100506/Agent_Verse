import asyncio
import logging
from app.core.celery_app import celery_app
from app.pipeline.orchestrator import run_verification_pipeline
from app.db.mongo import AsyncIOMotorClient
from app.config import settings

logger = logging.getLogger(__name__)

@celery_app.task(name="tasks.process_certificate_verification")
def process_certificate_verification(verification_id: str):
    """Celery task to run verification pipeline asynchronously."""
    logger.info(f"Starting Celery async verification task for ID: {verification_id}")
    
    async def async_runner():
        client = AsyncIOMotorClient(settings.MONGO_URI)
        db = client.get_database(settings.MONGO_DB_NAME)
        try:
            await run_verification_pipeline(verification_id, db)
        finally:
            client.close()

    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    loop.run_until_complete(async_runner())
    logger.info(f"Completed Celery verification task for ID: {verification_id}")
    return {"status": "completed", "verification_id": verification_id}
