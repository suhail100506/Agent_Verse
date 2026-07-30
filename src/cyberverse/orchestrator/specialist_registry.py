"""
specialist_registry.py — CyberVerse Specialist Registry
=========================================================
Maps specialist keys → their tool classes and provides
a synchronous `run_specialist()` helper used by the Flow.

Each specialist runs its own dedicated *risk aggregator* tool
(the last tool in its pipeline) directly — no LLM overhead —
and returns a structured SpecialistResult.
"""

from __future__ import annotations

import logging
import time
import json
from typing import Any, Dict, List, Optional

from cyberverse.orchestrator.models import RiskLevel, SpecialistResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Display Names
# ---------------------------------------------------------------------------

DISPLAY_NAMES: Dict[str, str] = {
    "certificate_verification_specialist": "Certificate Verification",
    "privacy_compliance_analyst": "Privacy Compliance Analyst",
    "malware_analysis_specialist": "Malware Analysis",
    "threat_detection_specialist": "Threat Detection",
    "identity_verification_specialist": "Identity Verification",
    "fraud_detection_specialist": "Fraud Detection",
    "phishing_detection_specialist": "Phishing Detection",
    "password_security_advisor": "Password Security Advisor",
    "incident_response_specialist": "Incident Response",
}

AVAILABLE_SPECIALISTS: List[str] = list(DISPLAY_NAMES.keys())

# Registry: specialist key → callable that imports + returns its risk tool class
# Using lazy imports so unused specialists don't slow startup.
_SPECIALIST_REGISTRY: Dict[str, str] = {
    "certificate_verification_specialist": "cyberverse.tools.certificate.tampering_tool:TamperingDetectionTool",
    "privacy_compliance_analyst": "cyberverse.tools.privacy.privacy_risk_tool:PrivacyRiskTool",
    "malware_analysis_specialist": "cyberverse.tools.malware.malware_risk_tool:MalwareRiskTool",
    "threat_detection_specialist": "cyberverse.tools.threat.threat_risk_tool:ThreatRiskTool",
    "identity_verification_specialist": "cyberverse.tools.identity.identity_risk_tool:IdentityRiskTool",
    "fraud_detection_specialist": "cyberverse.tools.fraud.fraud_risk_tool:FraudRiskTool",
    "phishing_detection_specialist": "cyberverse.tools.phishing.phishing_risk_tool:PhishingRiskTool",
    "password_security_advisor": "cyberverse.tools.password.password_risk_tool:PasswordRiskTool",
    "incident_response_specialist": "cyberverse.tools.incident.incident_response_tool:IncidentResponseTool",
}

# ---------------------------------------------------------------------------
# Specialist-specific input adapters
# Each adapter takes the global `inputs` dict and returns tool-specific kwargs.
# ---------------------------------------------------------------------------

def _to_json(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        return val
    return json.dumps(val)

def _adapt_certificate(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file_path": inputs.get("file_path") or (inputs.get("document", {}).get("file") if isinstance(inputs.get("document"), dict) else None) or "sample_certificate.pdf",
        "ocr_json": _to_json(inputs.get("ocr_data") or inputs.get("ocr")),
        "metadata_json": _to_json(inputs.get("metadata")),
        "qr_json": _to_json(inputs.get("qr_data") or inputs.get("qr")),
        "signature_json": _to_json(inputs.get("signature_data") or inputs.get("signature")),
    }

def _adapt_privacy(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "pii_json": _to_json(inputs.get("pii")),
        "secret_json": _to_json(inputs.get("secrets")),
        "compliance_json": _to_json(inputs.get("compliance")),
    }

def _adapt_malware(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "file_hash": _to_json(inputs.get("hash_result") or inputs.get("hash")),
        "yara": _to_json(inputs.get("yara_result") or inputs.get("yara")),
        "pe_analysis": _to_json(inputs.get("pe_result") or inputs.get("pe")),
        "virus_total": _to_json(inputs.get("vt_result") or inputs.get("vt")),
    }

def _adapt_threat(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ip_reputation": _to_json(inputs.get("ip")),
        "url_reputation": _to_json(inputs.get("url")),
        "dns_analysis": _to_json(inputs.get("dns")),
        "ioc_analysis": _to_json(inputs.get("ioc")),
    }

def _adapt_identity(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "document_json": _to_json(inputs.get("document")),
        "face_json": _to_json(inputs.get("face")),
        "liveness_json": _to_json(inputs.get("liveness")),
        "consistency_json": _to_json(inputs.get("consistency")),
    }

def _adapt_fraud(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "transaction_json": _to_json(inputs.get("transaction")),
        "behavioral_json": _to_json(inputs.get("behavioral")),
        "device_json": _to_json(inputs.get("device")),
        "takeover_json": _to_json(inputs.get("account_takeover") or inputs.get("takeover")),
    }

def _adapt_phishing(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "header_analysis": inputs.get("headers") or inputs.get("header") or {},
        "url_analysis": inputs.get("url_inspection") or inputs.get("url") or {},
        "domain_analysis": inputs.get("domain_reputation") or inputs.get("domain") or {},
        "content_analysis": inputs.get("content") or {},
    }

def _adapt_password(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "strength": inputs.get("strength") or inputs.get("password") or {},
        "policy": inputs.get("policy") or {},
        "leak": inputs.get("leak") or {},
        "mfa": inputs.get("mfa") or {},
    }

def _adapt_incident(inputs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "classification": inputs.get("classification") or {},
        "mitre": inputs.get("mitre") or {},
        "evidence": inputs.get("forensics") or inputs.get("evidence") or {},
        "containment": inputs.get("containment") or {},
    }

_INPUT_ADAPTERS = {
    "certificate_verification_specialist": _adapt_certificate,
    "privacy_compliance_analyst": _adapt_privacy,
    "malware_analysis_specialist": _adapt_malware,
    "threat_detection_specialist": _adapt_threat,
    "identity_verification_specialist": _adapt_identity,
    "fraud_detection_specialist": _adapt_fraud,
    "phishing_detection_specialist": _adapt_phishing,
    "password_security_advisor": _adapt_password,
    "incident_response_specialist": _adapt_incident,
}


# ---------------------------------------------------------------------------
# Score / risk extraction helpers
# ---------------------------------------------------------------------------

_SCORE_KEYS = [
    "overall_score", "security_score", "password_security_score", "incident_score",
    "trust_score", "risk_score", "fraud_score", "identity_score", "threat_score",
    "malware_score", "privacy_score", "phishing_score", "evidence_score",
]
_RISK_KEYS = ["overall_risk", "risk", "risk_level", "severity"]
_CONFIDENCE_KEYS = ["confidence"]


def _extract_score(result: Dict[str, Any]) -> int:
    for key in _SCORE_KEYS:
        v = result.get(key)
        if isinstance(v, (int, float)):
            return max(0, min(100, int(v)))
    return 50


def _extract_risk(result: Dict[str, Any]) -> RiskLevel:
    for key in _RISK_KEYS:
        v = result.get(key)
        if isinstance(v, str) and v.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            return v.upper()  # type: ignore[return-value]
    return "UNKNOWN"


def _extract_confidence(result: Dict[str, Any]) -> int:
    for key in _CONFIDENCE_KEYS:
        v = result.get(key)
        if isinstance(v, (int, float)):
            return max(0, min(100, int(v)))
    return 70


def _extract_list(result: Dict[str, Any], *keys: str) -> List[str]:
    for key in keys:
        v = result.get(key)
        if isinstance(v, list) and v:
            return [str(i) for i in v]
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _lazy_import_tool(specialist: str):
    """Lazily import and instantiate the risk tool for the given specialist."""
    module_path, class_name = _SPECIALIST_REGISTRY[specialist].split(":")
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()


def run_specialist(specialist: str, inputs: Dict[str, Any]) -> SpecialistResult:
    """
    Run the risk-aggregator tool for `specialist` with the provided inputs.
    Returns a SpecialistResult regardless of success/failure.
    """
    display = DISPLAY_NAMES.get(specialist, specialist)

    if specialist not in _SPECIALIST_REGISTRY:
        return SpecialistResult(
            specialist=specialist,
            display_name=display,
            success=False,
            risk_level="UNKNOWN",
            error=f"Unknown specialist: {specialist}",
        )

    adapter = _INPUT_ADAPTERS.get(specialist, lambda x: x)
    tool_inputs = adapter(inputs)

    t0 = time.monotonic()
    try:
        tool = _lazy_import_tool(specialist)
        import json
        raw_json: str = tool._run(**tool_inputs)
        raw: Dict[str, Any] = json.loads(raw_json) if isinstance(raw_json, str) else raw_json

        duration_ms = int((time.monotonic() - t0) * 1000)

        score = _extract_score(raw)
        risk = _extract_risk(raw)
        confidence = _extract_confidence(raw)
        findings = _extract_list(raw, "evidence", "findings", "alerts", "red_flags", "errors")
        recommendations = _extract_list(raw, "recommendations", "actions", "remediation")
        summary = raw.get("executive_summary", raw.get("summary", ""))

        dashboard = raw.get("dashboard", {})
        if not isinstance(dashboard, dict):
            dashboard = {}

        return SpecialistResult(
            specialist=specialist,
            display_name=display,
            success=raw.get("success", True),
            score=score,
            risk_level=risk,
            confidence=confidence,
            dashboard=dashboard,
            findings=findings,
            recommendations=recommendations,
            executive_summary=str(summary) if summary else "",
            raw_output=raw,
            error=raw.get("error"),
            duration_ms=duration_ms,
        )

    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        logger.exception("Specialist %s failed: %s", specialist, exc)
        return SpecialistResult(
            specialist=specialist,
            display_name=display,
            success=False,
            risk_level="UNKNOWN",
            error=str(exc),
            duration_ms=duration_ms,
        )


# Expose the registry mapping for introspection
SPECIALIST_REGISTRY = _SPECIALIST_REGISTRY
