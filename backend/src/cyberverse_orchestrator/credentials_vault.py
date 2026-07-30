import os
import json
import uuid
import base64
import datetime
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

CREDENTIALS_DB_PATH = Path(__file__).parent / "credentials_db.json"

ALLOWED_TYPES = {"groq_api_key", "smtp", "generic_api_key", "mongodb"}

SECRET_FIELDS_BY_TYPE = {
    "groq_api_key": ["api_key"],
    "generic_api_key": ["api_key"],
    "smtp": ["smtp_host", "smtp_port", "smtp_user", "smtp_pass", "recipient_default"],
    "mongodb": ["mongodb_uri", "database_name"],
}

PRIMARY_FIELD_BY_TYPE = {
    "groq_api_key": "api_key",
    "generic_api_key": "api_key",
    "smtp": "smtp_user",
    "mongodb": "mongodb_uri",
}


def _get_fernet() -> Fernet:
    key = os.getenv("VAULT_ENCRYPTION_KEY")
    if not key:
        # Dev-only fallback: generated once per process. Restarting the server
        # invalidates all previously-encrypted credentials, so this must never
        # be relied on outside local development.
        key = Fernet.generate_key().decode()
        os.environ["VAULT_ENCRYPTION_KEY"] = key
        logger.warning(
            "VAULT_ENCRYPTION_KEY not set - generated an ephemeral key for this "
            "process only. Set VAULT_ENCRYPTION_KEY in your .env for credentials "
            "to survive a server restart."
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def load_credentials() -> list:
    if CREDENTIALS_DB_PATH.exists():
        try:
            with open(CREDENTIALS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_credentials(records: list) -> None:
    with open(CREDENTIALS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _to_masked_record(record: dict) -> dict:
    return {
        "credential_id": record["credential_id"],
        "name": record["name"],
        "type": record["type"],
        "masked_preview": record["masked_preview"],
        "owner": record.get("owner", "default"),
        "created_at": record.get("created_at"),
        "last_used_at": record.get("last_used_at"),
    }


def create_credential(name: str, type: str, secret_fields: Dict[str, Any], owner: str = "default") -> dict:
    if type not in ALLOWED_TYPES:
        raise ValueError(f"Unsupported credential type '{type}'. Allowed: {sorted(ALLOWED_TYPES)}")

    expected_fields = SECRET_FIELDS_BY_TYPE[type]
    payload = {field: secret_fields.get(field, "") for field in expected_fields}

    primary_field = PRIMARY_FIELD_BY_TYPE[type]
    masked_preview = _mask(str(payload.get(primary_field, "")))

    fernet = _get_fernet()
    encrypted_payload = fernet.encrypt(json.dumps(payload).encode("utf-8")).decode("utf-8")

    record = {
        "credential_id": f"CRED-{uuid.uuid4().hex[:8].upper()}",
        "name": name,
        "type": type,
        "encrypted_payload": encrypted_payload,
        "masked_preview": masked_preview,
        "owner": owner,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "last_used_at": None,
    }

    records = load_credentials()
    records.insert(0, record)
    save_credentials(records)

    return _to_masked_record(record)


def list_credentials(owner: Optional[str] = None) -> List[dict]:
    records = load_credentials()
    if owner:
        records = [r for r in records if r.get("owner", "default") == owner]
    return [_to_masked_record(r) for r in records]


def delete_credential(credential_id: str) -> bool:
    records = load_credentials()
    remaining = [r for r in records if r.get("credential_id") != credential_id]
    if len(remaining) == len(records):
        return False
    save_credentials(remaining)
    return True


def find_credential_id_by_type(type: str) -> Optional[str]:
    """Returns the most recently added credential_id of the given type, or None."""
    records = load_credentials()
    for r in records:
        if r.get("type") == type:
            return r.get("credential_id")
    return None


def resolve_secret(credential_id: str) -> Optional[Dict[str, Any]]:
    """Decrypts and returns a credential's secret fields just-in-time.

    The return value must never be logged, persisted, or sent back to a client.
    """
    if not credential_id:
        return None

    records = load_credentials()
    for record in records:
        if record.get("credential_id") == credential_id:
            fernet = _get_fernet()
            try:
                decrypted = fernet.decrypt(record["encrypted_payload"].encode("utf-8"))
            except InvalidToken:
                logger.error(f"Failed to decrypt credential {credential_id} - key mismatch or corrupted payload.")
                return None
            record["last_used_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            save_credentials(records)
            secret_fields = json.loads(decrypted.decode("utf-8"))
            secret_fields["_type"] = record["type"]
            return secret_fields
    return None
