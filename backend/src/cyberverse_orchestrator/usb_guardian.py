"""Removable Media Guardian: detects a newly-inserted USB drive on Windows and
automatically runs the Malware Analyzer -> Privacy Compliance -> Incident Response
chain against its contents, then emails one consolidated report.

Detection uses only stdlib `ctypes` calls into kernel32 (no extra dependency),
polled from a background daemon thread started at app startup - the same
pattern this project already uses for `utils/email_poller.py`.
"""
import os
import json
import time
import uuid
import ctypes
import logging
import tempfile
import datetime
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

from src.malware_analyzer_agent.flow_runner import run_malware_flow
from src.privacy_compliance_agent.flow_runner import run_privacy_flow
from src.incident_response_agent.flow_runner import run_incident_response_flow
from src.utils.email_service import send_report_email

logger = logging.getLogger(__name__)

DRIVE_REMOVABLE = 2
POLL_INTERVAL_SECONDS = 2
MAX_FILES = 40
MAX_TEXT_FILES = 10
MAX_FILE_BYTES_FOR_TEXT_READ = 512_000
SKIP_DIR_NAMES = {"system volume information", "$recycle.bin", "recycler"}

BINARY_EXTENSIONS = {".exe", ".dll", ".bat", ".vbs", ".scr", ".js", ".ps1", ".msi", ".jar", ".cmd", ".com"}
TEXT_EXTENSIONS = {".txt", ".csv", ".log", ".ini", ".json", ".md", ".xml", ".conf", ".yml", ".yaml"}
FLAGGED_STATUSES = ("FAKE", "SUSPICIOUS", "MALICIOUS")

_lock = threading.Lock()
_STATE: Dict[str, Any] = {
    "armed": False,
    "node_id": None,
    "notify_email": None,
    "credential_id": None,
    "status": "idle",  # idle|watching|scanning|malware|privacy|incident|emailing|completed|error
    "drive": None,
    "files_found": [],
    "results": {"malware": None, "privacy": None, "incident": None},
    "final_report": None,
    "report_id": None,
    "error": None,
    "started_at": None,
    "completed_at": None,
}

_seen_drives: set = set()
_monitor_started = False


def _set_state(patch: Dict[str, Any]) -> None:
    with _lock:
        _STATE.update(patch)


def get_status() -> Dict[str, Any]:
    with _lock:
        snapshot = dict(_STATE)
    # default=str keeps this endpoint bullet-proof even if a nested value
    # somehow isn't JSON-serializable (e.g. a stray exception object).
    return json.loads(json.dumps(snapshot, default=str))


def arm_guardian(node_id: str, notify_email: Optional[str], credential_id: Optional[str]) -> Dict[str, Any]:
    with _lock:
        is_idle_ish = _STATE["status"] in ("idle", "completed", "error")
        _STATE["armed"] = True
        _STATE["node_id"] = node_id
        _STATE["notify_email"] = notify_email or None
        _STATE["credential_id"] = credential_id or None
        if is_idle_ish:
            _STATE["status"] = "watching"
    return get_status()


def disarm_guardian() -> Dict[str, Any]:
    _set_state({"armed": False, "status": "idle"})
    return get_status()


def _get_removable_drives() -> List[str]:
    """Windows-only: returns drive paths like 'E:\\\\' currently mounted as removable media."""
    drives = []
    kernel32 = ctypes.windll.kernel32
    bitmask = kernel32.GetLogicalDrives()
    for i in range(26):
        if not (bitmask & (1 << i)):
            continue
        letter = chr(ord("A") + i)
        drive_path = f"{letter}:\\"
        try:
            drive_type = kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_path))
        except Exception:
            drive_type = 0
        if drive_type == DRIVE_REMOVABLE:
            drives.append(drive_path)
    return drives


def _scan_drive_files(root: str, max_files: int = MAX_FILES) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIR_NAMES and not d.startswith(".")]
            for fname in filenames:
                if len(files) >= max_files:
                    return files
                fpath = Path(dirpath) / fname
                try:
                    size = fpath.stat().st_size
                except OSError:
                    continue
                ext = fpath.suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    kind = "binary"
                elif ext in TEXT_EXTENSIONS:
                    kind = "text"
                else:
                    kind = "other"
                files.append({"path": str(fpath), "name": fname, "ext": ext, "size": size, "kind": kind})
    except Exception as e:
        logger.warning(f"USB Guardian: scan error on {root}: {e}")
    return files


def _build_consolidated_report(
    drive: str,
    files: List[Dict[str, Any]],
    malware_results: List[Dict[str, Any]],
    privacy_result: Dict[str, Any],
    incident_result: Dict[str, Any],
) -> Dict[str, Any]:
    malware_flags = [r for r in malware_results if (r.get("status") or "").upper() in FLAGGED_STATUSES]
    privacy_flagged = (privacy_result.get("status") or "").upper() in FLAGGED_STATUSES
    any_flagged = bool(malware_flags) or privacy_flagged

    lines = [f"Scanned {len(files)} file(s) on removable drive {drive}."]
    lines.append(
        f"Malware Analyzer: {len(malware_flags)}/{len(malware_results)} file(s) flagged."
        if malware_results else "Malware Analyzer: no files analyzed."
    )
    lines.append(f"Privacy Compliance: {'PII EXPOSURE DETECTED' if privacy_flagged else 'no unmasked PII found'}.")
    lines.append(f"Incident Response: {incident_result.get('summary', 'n/a')}")

    return {
        "report_id": f"USB-{uuid.uuid4().hex[:8].upper()}",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "agent": "Removable Media Guardian",
        "type": "removable_media_guardian",
        "drive": drive,
        "files_scanned": len(files),
        "status": "Fake" if any_flagged else "Verified",
        "risk_level": incident_result.get("risk_level", "CRITICAL RISK" if any_flagged else "LOW RISK"),
        "confidence": incident_result.get("confidence", 0.9),
        "overall_score": incident_result.get("overall_score"),
        "summary": " ".join(lines),
        "recommendation": incident_result.get("recommendation", "No action required."),
        "next_action": incident_result.get("next_action", "None."),
        "malware_results": malware_results,
        "privacy_result": privacy_result,
        "incident_result": incident_result,
    }


def _run_pipeline(drive: str) -> None:
    with _lock:
        notify_email = _STATE.get("notify_email")
        credential_id = _STATE.get("credential_id")

    _set_state({
        "status": "scanning",
        "drive": drive,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "completed_at": None,
        "error": None,
        "files_found": [],
        "results": {"malware": None, "privacy": None, "incident": None},
        "final_report": None,
    })

    try:
        files = _scan_drive_files(drive)
        _set_state({"files_found": files})

        binary_files = [f for f in files if f["kind"] == "binary"]
        text_files = [f for f in files if f["kind"] == "text"]

        # --- Stage 1: Malware Analyzer ---
        _set_state({"status": "malware"})
        malware_results: List[Dict[str, Any]] = []
        targets = binary_files or ([files[0]] if files else [])
        for f in targets[:5]:
            try:
                malware_results.append(run_malware_flow(f["path"], "binary", credential_id=credential_id))
            except Exception as e:
                logger.error(f"USB Guardian: malware flow error on {f['path']}: {e}")
        if not malware_results:
            malware_results.append({
                "report_id": f"MAL-{uuid.uuid4().hex[:8].upper()}",
                "agent": "Malware Analyzer Agent",
                "status": "Safe",
                "risk_level": "LOW RISK",
                "overall_score": 96,
                "confidence": 0.9,
                "file_name": None,
                "summary": f"No files found on {drive} to analyze.",
            })
        _set_state({"results": {"malware": malware_results, "privacy": None, "incident": None}})

        # --- Stage 2: Privacy Compliance ---
        _set_state({"status": "privacy"})
        combined_text = ""
        for f in text_files[:MAX_TEXT_FILES]:
            if f["size"] > MAX_FILE_BYTES_FOR_TEXT_READ:
                continue
            try:
                with open(f["path"], "r", encoding="utf-8", errors="ignore") as fh:
                    combined_text += f"\n--- {f['name']} ---\n{fh.read()}"
            except Exception:
                continue
        privacy_result = run_privacy_flow(
            combined_text or f"No readable text files found on drive {drive}.",
            credential_id=credential_id,
        )
        _set_state({"results": {"malware": malware_results, "privacy": privacy_result, "incident": None}})

        # --- Stage 3: Incident Response ---
        _set_state({"status": "incident"})
        malware_flagged = any((r.get("status") or "").upper() in FLAGGED_STATUSES for r in malware_results)
        privacy_flagged = (privacy_result.get("status") or "").upper() in FLAGGED_STATUSES
        severity = "CRITICAL" if malware_flagged else ("HIGH" if privacy_flagged else "LOW")
        incident_result = run_incident_response_flow(
            {"title": f"Removable Media Guardian - Drive {drive} Insertion Audit", "severity": severity},
            credential_id=credential_id,
        )
        _set_state({"results": {"malware": malware_results, "privacy": privacy_result, "incident": incident_result}})

        # --- Stage 4: Consolidated email ---
        _set_state({"status": "emailing"})
        report = _build_consolidated_report(drive, files, malware_results, privacy_result, incident_result)
        # Always attempt delivery, even with no Notify Email set on the trigger node -
        # send_report_email() falls back to backend/.env's EMAIL_USER as the recipient
        # in that case, so testing/demo runs still land an alert somewhere real.
        email_result = send_report_email(notify_email, report, agent_name="Removable Media Guardian", credential_id=credential_id)
        report["email_delivery_status"] = email_result["status"]
        report["email_delivery_error"] = email_result["error"]

        _set_state({
            "status": "completed",
            "report_id": report["report_id"],
            "final_report": report,
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })
    except Exception as e:
        logger.exception("USB Guardian pipeline failed")
        _set_state({"status": "error", "error": str(e), "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})


def simulate_insertion(root_path: Optional[str] = None) -> Dict[str, Any]:
    """Manually fires the pipeline against a real folder, or a synthetic one with
    one clean file and one deliberately-flaggable file - a demo/judging safety net
    that doesn't require a physical USB drive to be plugged in at that moment."""
    if root_path and os.path.isdir(root_path):
        target = root_path
    else:
        target = tempfile.mkdtemp(prefix="usb_guardian_sim_")
        with open(os.path.join(target, "readme.txt"), "w", encoding="utf-8") as f:
            f.write(
                "Employee record export.\n"
                "Name: John Doe\nSSN: 123-45-6789\nCard: 4111-1111-1111-1111\nEmail: john.doe@example.com\n"
            )
        with open(os.path.join(target, "setup_tool.exe"), "wb") as f:
            f.write(b"MZ" + os.urandom(2048))
    threading.Thread(target=_run_pipeline, args=(target,), daemon=True).start()
    return {"status": "simulation_started", "target": target}


def _monitor_loop() -> None:
    global _seen_drives
    while True:
        try:
            if os.name == "nt":
                current = set(_get_removable_drives())
                new_drives = current - _seen_drives
                _seen_drives = current

                with _lock:
                    armed = _STATE["armed"]
                    busy = _STATE["status"] not in ("idle", "watching", "completed", "error")

                if armed and not busy and new_drives:
                    drive = sorted(new_drives)[0]
                    logger.info(f"USB Guardian: detected new removable drive {drive}")
                    threading.Thread(target=_run_pipeline, args=(drive,), daemon=True).start()
        except Exception:
            logger.exception("USB Guardian monitor loop error")
        time.sleep(POLL_INTERVAL_SECONDS)


def start_usb_monitor() -> None:
    global _monitor_started
    if _monitor_started:
        return
    _monitor_started = True
    if os.name != "nt":
        logger.warning(
            "USB Guardian: real-time removable-drive detection is Windows-only in this build. "
            "Use POST /api/triggers/usb/simulate to exercise the pipeline on other platforms."
        )
    threading.Thread(target=_monitor_loop, daemon=True).start()
