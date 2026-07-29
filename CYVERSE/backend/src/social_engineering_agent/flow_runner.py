import os
import json
import uuid
import datetime
import re
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from src.utils.llm_client import run_llm_agent
from src.utils.mongo_client import save_report

SOCIAL_ENGINEERING_REPORTS_DB_PATH = Path(__file__).parent / "social_engineering_reports_db.json"

DEFAULT_SYSTEM_PROMPT = """You are a social engineering and deepfake detection expert. You are given text content
(an email, message, or call transcript) and optionally metadata extracted from an attached image/video file.
Assess whether this exhibits social engineering manipulation tactics (urgency/pressure, authority impersonation,
too-good-to-be-true offers, requests for credentials/money/gift cards) or deepfake/media-tampering indicators.

Respond with ONLY a JSON object (no prose, no markdown fences) matching exactly this shape:
{
  "status": "Verified" | "Suspicious" | "Fake",
  "risk_level": "LOW RISK" | "MEDIUM RISK" | "CRITICAL RISK",
  "overall_score": <int 0-100>,
  "confidence": <float 0-1>,
  "checks": {
    "urgency_pressure_language": "...", "authority_impersonation": "...",
    "financial_request_pattern": "...", "media_tampering_indicators": "..."
  },
  "summary": "...",
  "recommendation": "...",
  "next_action": "..."
}
Use "status": "Verified" for benign content and "Fake" for a confirmed social-engineering/deepfake attempt
(matching this platform's status vocabulary)."""

URGENCY_PATTERNS = [
    r"act now", r"urgent(?:ly)?", r"immediately", r"verify your account",
    r"failure to (?:respond|comply)", r"suspend(?:ed)? your account", r"limited time",
]

IMPERSONATION_PATTERNS = [
    r"this is (?:your )?(?:ceo|cfo|it support|it department|bank)", r"on behalf of",
    r"official (?:notice|request) from", r"security team",
]

FINANCIAL_REQUEST_PATTERNS = [
    r"wire transfer", r"gift card", r"bank details", r"routing number",
    r"send (?:payment|money|funds)", r"crypto(?:currency)? wallet",
]


def load_local_social_engineering_reports() -> list:
    if SOCIAL_ENGINEERING_REPORTS_DB_PATH.exists():
        try:
            with open(SOCIAL_ENGINEERING_REPORTS_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_local_social_engineering_report(report: dict) -> None:
    reports = load_local_social_engineering_reports()
    reports.insert(0, report)
    with open(SOCIAL_ENGINEERING_REPORTS_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def _match_any(patterns, text_lower: str) -> list:
    return [p for p in patterns if re.search(p, text_lower)]


def extract_media_metadata(file_path: Optional[str]) -> Dict[str, Any]:
    metadata = {}
    if not file_path or not HAS_PIL or not os.path.exists(file_path):
        return metadata
    try:
        with Image.open(file_path) as img:
            metadata["width"] = img.width
            metadata["height"] = img.height
            metadata["format"] = img.format
            exif = img._getexif() if hasattr(img, '_getexif') and img._getexif() else {}
            if exif:
                for tag_id, val in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if tag in ["Software", "Artist", "ImageDescription", "UserComment"]:
                        metadata[tag.lower()] = str(val)
    except Exception:
        pass
    return metadata


def run_social_engineering_flow(
    input_text: str = "",
    file_path: Optional[str] = None,
    credential_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    text_lower = (input_text or "").lower()
    metadata = extract_media_metadata(file_path)

    urgency_hits = _match_any(URGENCY_PATTERNS, text_lower)
    impersonation_hits = _match_any(IMPERSONATION_PATTERNS, text_lower)
    financial_hits = _match_any(FINANCIAL_REQUEST_PATTERNS, text_lower)

    editor_software = metadata.get("software", "")
    media_tampering_flag = bool(editor_software) and any(t in editor_software.lower() for t in ["photoshop", "gimp", "deepfacelab", "faceswap"])

    signal_count = len(urgency_hits) + len(impersonation_hits) + len(financial_hits) + (1 if media_tampering_flag else 0)

    if signal_count == 0:
        status = "Verified"
        risk_level = "LOW RISK"
        overall_score = 95
        confidence = 0.96
        checks = {
            "urgency_pressure_language": "Passed - No urgency or pressure tactics detected.",
            "authority_impersonation": "Passed - No impersonation phrasing detected.",
            "financial_request_pattern": "Passed - No suspicious financial/credential requests detected.",
            "media_tampering_indicators": "Passed - No media manipulation software fingerprints found." if file_path else "Passed - No media attached for analysis."
        }
        summary = "Social engineering scan found no manipulation tactics or deepfake indicators in the provided content."
        recommendation = "No action required."
        next_action = "Archive as benign communication."
    elif signal_count <= 2:
        status = "Suspicious"
        risk_level = "MEDIUM RISK"
        overall_score = 58
        confidence = 0.85
        checks = {
            "urgency_pressure_language": f"Warning - Detected phrases: {urgency_hits}" if urgency_hits else "Passed - No urgency tactics detected.",
            "authority_impersonation": f"Warning - Detected phrases: {impersonation_hits}" if impersonation_hits else "Passed - No impersonation phrasing detected.",
            "financial_request_pattern": f"Warning - Detected phrases: {financial_hits}" if financial_hits else "Passed - No suspicious financial requests detected.",
            "media_tampering_indicators": f"Warning - Editing software fingerprint: {editor_software}" if media_tampering_flag else "Passed - No media manipulation fingerprints found."
        }
        summary = "Social engineering scan flagged one or more manipulation indicators requiring human review."
        recommendation = "Have a security analyst manually review this communication before acting on it."
        next_action = "Queue for Level-1 SOC analyst triage."
    else:
        status = "Fake"
        risk_level = "CRITICAL RISK"
        overall_score = 22
        confidence = 0.95
        checks = {
            "urgency_pressure_language": f"Failed - Detected phrases: {urgency_hits}",
            "authority_impersonation": f"Failed - Detected phrases: {impersonation_hits}",
            "financial_request_pattern": f"Failed - Detected phrases: {financial_hits}",
            "media_tampering_indicators": f"Failed - Editing software fingerprint: {editor_software}" if media_tampering_flag else "Passed - No media manipulation fingerprints found."
        }
        summary = "CRITICAL SOCIAL ENGINEERING ALERT: Multiple manipulation tactics and/or media tampering indicators detected."
        recommendation = "Do not comply with any request in this communication. Report to Security immediately."
        next_action = "Escalate to Security Awareness & Incident Response Team."

    llm_result = run_llm_agent(
        system_prompt=system_prompt or DEFAULT_SYSTEM_PROMPT,
        user_prompt=(
            f"Text content: {input_text[:4000]}\n"
            f"Attached media metadata: {metadata or 'none'}\n"
            f"Heuristic signal count: {signal_count}"
        ),
        credential_id=credential_id,
        model=model or "llama-3.3-70b-versatile",
        expect_json=True,
    )
    if llm_result["ok"] and isinstance(llm_result["content"], dict):
        d = llm_result["content"]
        status = d.get("status", status)
        risk_level = d.get("risk_level", risk_level)
        overall_score = d.get("overall_score", overall_score)
        confidence = d.get("confidence", confidence)
        checks = d.get("checks", checks)
        summary = d.get("summary", summary)
        recommendation = d.get("recommendation", recommendation)
        next_action = d.get("next_action", next_action)

    report_id = f"SOCENG-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    final_report = {
        "report_id": report_id,
        "created_at": timestamp,
        "agent": "Social Engineering / Deepfake Detection Agent",
        "type": "social_engineering",
        "input_excerpt": (input_text or "")[:300],
        "attached_media": os.path.basename(file_path) if file_path else None,
        "status": status,
        "risk_level": risk_level,
        "confidence": confidence,
        "overall_score": overall_score,
        "checks": checks,
        "summary": summary,
        "recommendation": recommendation,
        "next_action": next_action,
        "llm_reasoning_used": llm_result["ok"],
        "llm_source": llm_result["source"]
    }

    save_local_social_engineering_report(final_report)

    final_report["mongodb_saved"] = save_report("social_engineering_reports", final_report)

    return final_report
