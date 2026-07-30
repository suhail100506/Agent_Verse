import logging
from typing import Dict, Any, List
from src.utils.mongo_client import save_report, get_mongo_collection

logger = logging.getLogger(__name__)

COLLECTION_NAME = "google_drive_verifications"


def save_workflow_run_to_mongo(record: Dict[str, Any]) -> bool:
    """Inserts a completed verification workflow run into MongoDB Compass collection."""
    try:
        success = save_report(COLLECTION_NAME, record)
        if success:
            logger.info(f"Persisted workflow run '{record.get('workflow_id')}' to MongoDB '{COLLECTION_NAME}'")
        return success
    except Exception as e:
        logger.warning(f"Failed to persist workflow run to MongoDB: {e}")
        return False


def get_workflow_history_from_mongo(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent verification runs from MongoDB Compass."""
    collection = get_mongo_collection(COLLECTION_NAME)
    if collection is None:
        return []

    try:
        cursor = collection.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
        return list(cursor)
    except Exception as e:
        logger.warning(f"Error fetching history from MongoDB: {e}")
        return []
