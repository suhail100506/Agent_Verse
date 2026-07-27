from motor.motor_asyncio import AsyncIOMotorClient
import logging
from bson import ObjectId
from app.config import settings
from app.db.in_memory_db import InMemoryDatabase

logger = logging.getLogger(__name__)

class MongoDatabase:
    client: AsyncIOMotorClient = None
    db = None

db_instance = MongoDatabase()

def to_object_id(val):
    if val is None:
        return None
    if isinstance(val, ObjectId):
        return val
    if isinstance(val, str) and ObjectId.is_valid(val):
        return ObjectId(val)
    return str(val)

async def connect_to_mongo():
    logger.info("Attempting MongoDB connection...")
    try:
        # Set short server selection timeout (2000ms) to detect offline Mongo quickly
        client = AsyncIOMotorClient(settings.MONGO_URI, serverSelectionTimeoutMS=2000)
        # Test ping
        await client.admin.command('ping')
        db_instance.client = client
        db_instance.db = client.get_database(settings.MONGO_DB_NAME)
        
        # Create indexes
        await db_instance.db.users.create_index("email", unique=True)
        await db_instance.db.certificates.create_index("file_hash_sha256", unique=True)
        await db_instance.db.verification_records.create_index("certificate_id")
        await db_instance.db.verification_records.create_index([
            ("extracted_data.certificate_number", 1),
            ("extracted_data.institution", 1)
        ])
        logger.info("MongoDB connection established and indexes verified.")
    except Exception as e:
        logger.warning(f"MongoDB not available ({e}). Falling back to high-performance In-Memory Database store.")
        db_instance.db = InMemoryDatabase()

async def close_mongo_connection():
    if db_instance.client:
        db_instance.client.close()
        logger.info("MongoDB connection closed.")

def get_database():
    if db_instance.db is None:
        db_instance.db = InMemoryDatabase()
    return db_instance.db
