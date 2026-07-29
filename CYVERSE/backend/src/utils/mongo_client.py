import os
import logging
from typing import Optional

from src.cyberverse_orchestrator.credentials_vault import find_credential_id_by_type, resolve_secret

logger = logging.getLogger(__name__)

_client_cache: dict = {}


def _resolve_connection() -> tuple[str, str]:
    """Resolves (mongo_uri, database_name).

    Resolution order: a vault-stored "mongodb" credential (most recently added),
    then MONGODB_URI/DATABASE_NAME env vars, then a localhost default.
    """
    mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    database_name = os.getenv("DATABASE_NAME", "certificate_verifier")

    credential_id = find_credential_id_by_type("mongodb")
    if credential_id:
        secret = resolve_secret(credential_id)
        if secret and secret.get("mongodb_uri"):
            mongo_uri = secret["mongodb_uri"]
            database_name = secret.get("database_name") or database_name

    return mongo_uri, database_name


def get_mongo_collection(collection_name: str):
    """Returns a pymongo Collection, or None if Mongo is unreachable/unconfigured. Never raises."""
    mongo_uri, database_name = _resolve_connection()

    try:
        from pymongo import MongoClient
        client = _client_cache.get(mongo_uri)
        if client is None:
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1200)
            _client_cache[mongo_uri] = client
        client.admin.command('ping')
        return client[database_name][collection_name]
    except Exception as e:
        logger.debug(f"MongoDB unavailable ({mongo_uri}): {e}")
        return None


def save_report(collection_name: str, report: dict) -> bool:
    """Best-effort insert into MongoDB (for viewing live in MongoDB Compass). Returns
    True/False, never raises - callers should keep working even if Mongo is down."""
    collection = get_mongo_collection(collection_name)
    if collection is None:
        return False
    try:
        collection.insert_one(report.copy())
        return True
    except Exception as e:
        logger.debug(f"MongoDB insert failed for collection '{collection_name}': {e}")
        return False
