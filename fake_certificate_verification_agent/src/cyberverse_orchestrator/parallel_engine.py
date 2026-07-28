import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

from src.malware_analyzer_agent.flow_runner import run_malware_flow
from src.threat_detection_agent.flow_runner import run_threat_flow
from src.phishing_detection_agent.flow_runner import run_phishing_flow
from src.privacy_compliance_agent.flow_runner import run_privacy_flow
from src.password_advisor_agent.flow_runner import run_password_flow
from src.fraud_detection_agent.flow_runner import run_fraud_flow
from src.incident_response_agent.flow_runner import run_incident_response_flow
from src.fake_certificate_verification_agent.flow_runner import run_certificate_flow
from src.identity_verification_agent.flow_runner import run_identity_flow


def safe_execute(agent_fn, *args, **kwargs) -> Dict[str, Any]:
    """Fault-tolerant wrapper executing an agent task with error fallback."""
    try:
        return agent_fn(*args, **kwargs)
    except Exception as e:
        return {
            "status": "Warning",
            "risk_level": "UNKNOWN",
            "error": str(e),
            "summary": f"Sub-agent execution timed out or encountered warning: {str(e)}",
            "checks": {"fault_tolerance": f"Sub-agent caught exception gracefully: {str(e)}"}
        }


def run_parallel_investigation(prompt: str, file_path: Optional[str] = None, selfie_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes multiple relevant security sub-agents concurrently in parallel threads,
    combining context for high-speed multi-agent analysis (<30 seconds).
    """
    with ThreadPoolExecutor(max_workers=6) as executor:
        f_malware = executor.submit(safe_execute, run_malware_flow, file_path or "sample.exe")
        f_threat = executor.submit(safe_execute, run_threat_flow, prompt)
        f_phish = executor.submit(safe_execute, run_phishing_flow, prompt)
        f_privacy = executor.submit(safe_execute, run_privacy_flow, prompt)

        r_malware = f_malware.result()
        r_threat = f_threat.result()
        r_phish = f_phish.result()
        r_privacy = f_privacy.result()

    results = {
        "malware_analyzer": r_malware,
        "threat_detector": r_threat,
        "phishing_detector": r_phish,
        "privacy_compliance": r_privacy
    }

    return results
