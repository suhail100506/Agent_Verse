import os
import datetime
import uuid
from typing import Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient

import logging

logger = logging.getLogger(__name__)

async def save_incident_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Saves the generated incident response report to MongoDB asynchronously.
    """
    report_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    final_report = {
        "report_id": report_id,
        "created_at": timestamp,
        **report_data
    }
    
    try:
        mongo_uri = os.getenv("MONGODB_URI")
        if not mongo_uri:
            final_report["mongodb_saved"] = False
            final_report["mongodb_error"] = "MONGODB_URI not set"
            return final_report
            
        client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=5000)
        db_name = os.getenv("MONGODB_DB_NAME", "cyberverse_ai")
        db = client[db_name]
        collection = db["incident_response_reports"]
        
        await collection.insert_one(final_report.copy())
        final_report["mongodb_saved"] = True
        
        # We need to remove the _id that Motor automatically injects 
        # so it's safely JSON serializable for FastAPI responses
        if "_id" in final_report:
            final_report["_id"] = str(final_report["_id"])
            
    except Exception as e:
        logger.error(f"Failed to save incident report to MongoDB: {e}")
        final_report["mongodb_saved"] = False
        final_report["mongodb_error"] = str(e)
        
    return final_report
