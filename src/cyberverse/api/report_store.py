"""
report_store.py — Hybrid MongoDB + File + Memory Report Persistence
=====================================================================
Provides save/load/list operations for OrchestratorReports.

Storage Pipeline:
  1. In-Memory Cache (fast reads)
  2. MongoDB Database `cyberverse.reports` (if MongoDB running / MongoDB Compass)
  3. JSON Files `reports/{report_id}.json` (fallback disk storage)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from cyberverse.orchestrator.models import OrchestratorReport, ReportSummary

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MongoDB setup (lazy initialization)
# ---------------------------------------------------------------------------

_MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
_DB_NAME = os.environ.get("MONGODB_DB", "cyberverse")
_COLLECTION_NAME = "reports"

_mongo_client = None
_mongo_coll = None
_mongo_checked = False


def _get_mongo_collection():
    """Lazily connect to MongoDB if available."""
    global _mongo_client, _mongo_coll, _mongo_checked
    if _mongo_checked:
        return _mongo_coll

    _mongo_checked = True
    try:
        import pymongo
        client = pymongo.MongoClient(_MONGODB_URI, serverSelectionTimeoutMS=2000)
        # Test connection
        client.admin.command("ping")
        _mongo_client = client
        _mongo_coll = client[_DB_NAME][_COLLECTION_NAME]
        logger.info("Successfully connected to MongoDB at %s (DB: %s)", _MONGODB_URI, _DB_NAME)
    except Exception as exc:
        logger.info("MongoDB not connected (%s). Falling back to JSON file storage.", exc)
        _mongo_coll = None

    return _mongo_coll


# ---------------------------------------------------------------------------
# Storage path
# ---------------------------------------------------------------------------

_REPORTS_DIR = Path(os.environ.get("CYBERVERSE_REPORTS_DIR", "reports/"))


def _ensure_dir() -> None:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

_cache: Dict[str, OrchestratorReport] = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_report(report: OrchestratorReport) -> str:
    """Persist report to memory, MongoDB, and disk. Returns report_id."""
    if not report.report_id:
        report.report_id = str(uuid.uuid4())

    _cache[report.report_id] = report

    # 1. MongoDB
    coll = _get_mongo_collection()
    if coll is not None:
        try:
            doc = json.loads(report.model_dump_json())
            doc["_id"] = report.report_id
            coll.replace_one({"_id": report.report_id}, doc, upsert=True)
            logger.info("Report %s saved to MongoDB collection '%s.reports'", report.report_id, _DB_NAME)
        except Exception as exc:
            logger.warning("Could not save report to MongoDB: %s", exc)

    # 2. JSON File fallback
    try:
        _ensure_dir()
        path = _REPORTS_DIR / f"{report.report_id}.json"
        path.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        logger.debug("Report saved to disk at %s", path)
    except Exception as exc:
        logger.warning("Could not persist report to disk: %s", exc)

    return report.report_id


def get_report(report_id: str) -> Optional[OrchestratorReport]:
    """Retrieve a report by ID. Checks memory -> MongoDB -> Disk."""
    if report_id in _cache:
        return _cache[report_id]

    # 1. MongoDB
    coll = _get_mongo_collection()
    if coll is not None:
        try:
            doc = coll.find_one({"_id": report_id})
            if doc:
                doc.pop("_id", None)
                report = OrchestratorReport.model_validate(doc)
                _cache[report_id] = report
                return report
        except Exception as exc:
            logger.warning("Could not read report %s from MongoDB: %s", report_id, exc)

    # 2. Disk
    try:
        path = _REPORTS_DIR / f"{report_id}.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            report = OrchestratorReport.model_validate(data)
            _cache[report_id] = report
            return report
    except Exception as exc:
        logger.warning("Could not load report %s from disk: %s", report_id, exc)

    return None


def list_reports(limit: int = 50, offset: int = 0) -> List[ReportSummary]:
    """
    List report summaries sorted by created_at descending.
    Merges MongoDB, disk files, and in-memory cache.
    """
    coll = _get_mongo_collection()
    if coll is not None:
        try:
            cursor = coll.find({}, {"_id": 0}).sort("created_at", -1).skip(offset).limit(limit)
            reports_from_mongo = []
            for doc in cursor:
                try:
                    report = OrchestratorReport.model_validate(doc)
                    _cache[report.report_id] = report
                    reports_from_mongo.append(report)
                except Exception:
                    pass
            if reports_from_mongo:
                return [
                    ReportSummary(
                        report_id=r.report_id,
                        label=r.label,
                        created_at=r.created_at,
                        overall_risk=r.platform_risk.overall_risk,
                        overall_score=r.platform_risk.overall_score,
                        specialists_run=r.platform_risk.specialists_run,
                        status=r.status,
                    )
                    for r in reports_from_mongo
                ]
        except Exception as exc:
            logger.warning("Could not list reports from MongoDB: %s", exc)

    # Fallback: scan disk files
    try:
        _ensure_dir()
        for path in _REPORTS_DIR.glob("*.json"):
            rid = path.stem
            if rid not in _cache:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    report = OrchestratorReport.model_validate(data)
                    _cache[rid] = report
                except Exception:
                    pass
    except Exception as exc:
        logger.warning("Could not scan reports directory: %s", exc)

    all_reports = sorted(
        _cache.values(),
        key=lambda r: r.created_at,
        reverse=True,
    )

    page = all_reports[offset : offset + limit]

    return [
        ReportSummary(
            report_id=r.report_id,
            label=r.label,
            created_at=r.created_at,
            overall_risk=r.platform_risk.overall_risk,
            overall_score=r.platform_risk.overall_score,
            specialists_run=r.platform_risk.specialists_run,
            status=r.status,
        )
        for r in page
    ]


def delete_report(report_id: str) -> bool:
    """Delete a report from memory, MongoDB, and disk. Returns True if deleted."""
    found = False
    if report_id in _cache:
        del _cache[report_id]
        found = True

    coll = _get_mongo_collection()
    if coll is not None:
        try:
            res = coll.delete_one({"_id": report_id})
            if res.deleted_count > 0:
                found = True
        except Exception as exc:
            logger.warning("Could not delete report from MongoDB: %s", exc)

    try:
        path = _REPORTS_DIR / f"{report_id}.json"
        if path.exists():
            path.unlink()
            found = True
    except Exception as exc:
        logger.warning("Could not delete report file: %s", exc)

    return found


def report_count() -> int:
    """Return total number of stored reports."""
    coll = _get_mongo_collection()
    if coll is not None:
        try:
            return coll.count_documents({})
        except Exception:
            pass
    return len(_cache)
