import os
import logging
from typing import Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

# Using a global cache for the database client
_client: AsyncIOMotorClient | None = None

def get_database():
    global _client
    if _client is None:
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        # Initialize Motor client for Async MongoDB operations
        _client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=2000)
    
    db_name = os.getenv("DATABASE_NAME", "cyberverse_agents")
    return _client[db_name]

async def log_analysis_request(
    input_data: Dict[str, Any],
    output_data: Dict[str, Any],
    execution_time_ms: float,
    status: str
) -> bool:
    """Log the phishing analysis request to MongoDB asynchronously."""
    try:
        db = get_database()
        collection = db.phishing_analysis_logs
        
        log_entry = {
            "input": input_data,
            "output": output_data,
            "execution_time_ms": execution_time_ms,
            "status": status,
            # Let MongoDB automatically set _id, and motor handles datetime injection well if needed,
            # but we can rely on standard motor dict insert.
        }
        
        from datetime import datetime, timezone
        log_entry["timestamp"] = datetime.now(timezone.utc)
        
        await collection.insert_one(log_entry)
        return True
    except Exception as e:
        logger.error(f"Failed to log analysis request to MongoDB: {e}")
        return False
