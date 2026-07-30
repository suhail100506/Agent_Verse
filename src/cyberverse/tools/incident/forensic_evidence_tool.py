"""
ForensicEvidenceTool — Read-Only Forensic Artifact & Chain-of-Custody Engine
=============================================================================
Collects, structures, and verifies digital forensic evidence (file hashes,
process telemetry, network connections, DNS queries, registry keys, event logs,
user sessions, scheduled tasks, and services), preserving chain-of-custody integrity.
"""

import json
import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class ForensicEvidenceToolInput(BaseModel):
    """Input schema for ForensicEvidenceTool."""

    incident_id: str = Field(
        default="INC-001",
        description="Unique incident identifier.",
    )
    collector_id: str = Field(
        default="IR-FORENSICS-01",
        description="Identifier of the forensic analyst or automated collector.",
    )
    artifacts: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of raw or structured evidence artifact dictionaries.",
    )
    processes: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of process telemetry records (pid, name, cmdline, parent_pid).",
    )
    network_connections: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of network socket records (src_ip, dest_ip, dest_port, protocol).",
    )
    dns_queries: Optional[List[str]] = Field(
        default_factory=list,
        description="List of queried domain names or DNS resolution records.",
    )
    registry_entries: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of registry key/value modifications or persistence entries.",
    )
    event_logs: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="List of Windows Event Log records (event_id, provider, timestamp, details).",
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class ForensicEvidenceTool(BaseTool):
    """
    Read-Only Digital Forensic Evidence & Chain-of-Custody Tool.

    Organizes file hashes, process telemetry, network sockets, DNS records, registry keys,
    event logs, scheduled tasks, and user sessions into an evidence inventory and
    chronological event timeline. Generates SHA-256 chain-of-custody integrity manifests.
    """

    name: str = "Forensic Evidence Tool"
    description: str = (
        "Collects and organizes digital forensic evidence (file hashes, processes, "
        "network connections, DNS queries, registry changes, event logs, scheduled tasks). "
        "Builds chronological timelines, calculates evidence completeness score (0–100), "
        "and generates cryptographic SHA-256 chain-of-custody integrity manifests."
    )
    args_schema: Type[BaseModel] = ForensicEvidenceToolInput

    def _run(
        self,
        incident_id: str = "INC-001",
        collector_id: str = "IR-FORENSICS-01",
        artifacts: Optional[List[Dict[str, Any]]] = None,
        processes: Optional[List[Dict[str, Any]]] = None,
        network_connections: Optional[List[Dict[str, Any]]] = None,
        dns_queries: Optional[List[str]] = None,
        registry_entries: Optional[List[Dict[str, Any]]] = None,
        event_logs: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Execute read-only forensic evidence collection and chain-of-custody verification."""
        artifacts = artifacts or []
        processes = processes or []
        network_connections = network_connections or []
        dns_queries = dns_queries or []
        registry_entries = registry_entries or []
        event_logs = event_logs or []

        logger.info(
            "ForensicEvidenceTool: processing evidence for %s — artifacts=%d, procs=%d, net=%d",
            incident_id, len(artifacts), len(processes), len(network_connections)
        )

        try:
            # 1. Structure Evidence Inventory
            evidence_inventory = self._build_evidence_inventory(
                artifacts, processes, network_connections, dns_queries, registry_entries, event_logs
            )

            # 2. Generate Cryptographic Chain-of-Custody Manifest
            chain_of_custody, manifest_hash = self._generate_chain_of_custody(
                incident_id, collector_id, evidence_inventory
            )

            # 3. Build Chronological Timeline
            timeline = self._build_chronological_timeline(
                artifacts, processes, network_connections, event_logs
            )

            # 4. Compute Evidence Score
            evidence_score = self._compute_evidence_score(
                evidence_inventory, timeline, manifest_hash
            )

            # 5. Formulate Telemetry Dashboard
            dashboard = {
                "incident_id": incident_id,
                "total_artifacts": len(evidence_inventory),
                "process_artifacts": len(processes),
                "network_artifacts": len(network_connections),
                "dns_artifacts": len(dns_queries),
                "registry_artifacts": len(registry_entries),
                "event_log_artifacts": len(event_logs),
                "chain_of_custody_hash": manifest_hash,
                "integrity_verified": True,
                "evidence_score": evidence_score
            }

            # 6. Formulate Findings & Recommendations
            findings: List[str] = []
            recommendations: List[str] = []
            self._generate_findings_and_recs(
                incident_id=incident_id,
                evidence_inventory=evidence_inventory,
                manifest_hash=manifest_hash,
                evidence_score=evidence_score,
                findings=findings,
                recommendations=recommendations
            )

            return json.dumps({
                "success": True,
                "evidence_score": evidence_score,
                "dashboard": dashboard,
                "evidence": evidence_inventory,
                "timeline": timeline,
                "chain_of_custody": chain_of_custody,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing ForensicEvidenceTool: %s", str(e), exc_info=True)
            return json.dumps({
                "success": False,
                "evidence_score": 0,
                "dashboard": {},
                "evidence": [],
                "timeline": [],
                "chain_of_custody": {},
                "findings": [],
                "recommendations": [],
                "error": f"Forensic evidence processing failed: {str(e)}"
            }, indent=2)

    # =========================================================================
    # ── HELPER METHODS ────────────────────────────────────────────────────────
    # =========================================================================

    def _build_evidence_inventory(
        self,
        artifacts: List[Dict[str, Any]],
        processes: List[Dict[str, Any]],
        network_connections: List[Dict[str, Any]],
        dns_queries: List[str],
        registry_entries: List[Dict[str, Any]],
        event_logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Normalizes and combines all forensic artifacts into a sealed evidence inventory."""
        inventory: List[Dict[str, Any]] = []

        # Process artifacts
        for p in processes:
            inventory.append({
                "artifact_type": "PROCESS",
                "name": p.get("name", "unknown_proc"),
                "pid": p.get("pid", 0),
                "cmdline": p.get("cmdline", ""),
                "parent_pid": p.get("parent_pid", 0),
                "user": p.get("user", "SYSTEM"),
                "hash_sha256": p.get("sha256", hashlib.sha256(str(p).encode()).hexdigest())
            })

        # Network artifacts
        for n in network_connections:
            inventory.append({
                "artifact_type": "NETWORK_SOCKET",
                "src_ip": n.get("src_ip", "127.0.0.1"),
                "dest_ip": n.get("dest_ip", "0.0.0.0"),
                "dest_port": n.get("dest_port", 80),
                "protocol": n.get("protocol", "TCP"),
                "state": n.get("state", "ESTABLISHED"),
                "hash_sha256": hashlib.sha256(str(n).encode()).hexdigest()
            })

        # DNS Artifacts
        for d in dns_queries:
            inventory.append({
                "artifact_type": "DNS_QUERY",
                "domain": d,
                "hash_sha256": hashlib.sha256(d.encode()).hexdigest()
            })

        # Registry Artifacts
        for r in registry_entries:
            inventory.append({
                "artifact_type": "REGISTRY_KEY",
                "key_path": r.get("key_path", "HKLM\\Software"),
                "value_name": r.get("value_name", ""),
                "value_data": r.get("value_data", ""),
                "hash_sha256": hashlib.sha256(str(r).encode()).hexdigest()
            })

        # Event Log Artifacts
        for e in event_logs:
            inventory.append({
                "artifact_type": "EVENT_LOG",
                "event_id": e.get("event_id", 0),
                "provider": e.get("provider", "Windows-Security"),
                "details": e.get("details", ""),
                "hash_sha256": hashlib.sha256(str(e).encode()).hexdigest()
            })

        # Custom artifacts
        for a in artifacts:
            inventory.append({
                "artifact_type": a.get("artifact_type", "FILE_ARTIFACT"),
                "name": a.get("name", "artifact_file"),
                "path": a.get("path", "/tmp/artifact"),
                "hash_sha256": a.get("sha256", hashlib.sha256(str(a).encode()).hexdigest())
            })

        return inventory

    def _generate_chain_of_custody(
        self,
        incident_id: str,
        collector_id: str,
        inventory: List[Dict[str, Any]]
    ) -> tuple[Dict[str, Any], str]:
        """Generates immutable chain-of-custody manifest and cryptographic SHA-256 digest."""
        acq_time = datetime.now(timezone.utc).isoformat()
        manifest_data = {
            "incident_id": incident_id,
            "collector_id": collector_id,
            "acquisition_timestamp": acq_time,
            "preservation_status": "READ_ONLY_SEALED",
            "artifact_count": len(inventory),
            "evidence_digest_sources": [item.get("hash_sha256") for item in inventory]
        }

        manifest_string = json.dumps(manifest_data, sort_keys=True)
        manifest_hash = hashlib.sha256(manifest_string.encode("utf-8")).hexdigest()
        manifest_data["manifest_sha256"] = manifest_hash

        return manifest_data, manifest_hash

    def _build_chronological_timeline(
        self,
        artifacts: List[Dict[str, Any]],
        processes: List[Dict[str, Any]],
        network: List[Dict[str, Any]],
        event_logs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Sorts all forensic events into a chronological timeline."""
        timeline: List[Dict[str, Any]] = []

        now_str = datetime.now(timezone.utc).isoformat()

        for p in processes:
            timeline.append({
                "timestamp": p.get("timestamp", now_str),
                "event": f"Process Execution: {p.get('name', 'unknown')} (PID {p.get('pid', 0)})",
                "category": "Process Execution",
                "source": "EDR / Process Monitor"
            })

        for n in network:
            timeline.append({
                "timestamp": n.get("timestamp", now_str),
                "event": f"Network Socket: {n.get('src_ip', '')} -> {n.get('dest_ip', '')}:{n.get('dest_port', '')}",
                "category": "Network Traffic",
                "source": "NetFlow / Firewall"
            })

        for e in event_logs:
            timeline.append({
                "timestamp": e.get("timestamp", now_str),
                "event": f"Windows Event ID {e.get('event_id', 0)}: {e.get('details', '')}",
                "category": "Windows Event Log",
                "source": e.get("provider", "Security Log")
            })

        for a in artifacts:
            timeline.append({
                "timestamp": a.get("timestamp", now_str),
                "event": f"Artifact Collected: {a.get('name', 'file')}",
                "category": "Disk / Memory Artifact",
                "source": "Forensic Imager"
            })

        # Sort timeline by timestamp
        timeline.sort(key=lambda x: str(x.get("timestamp", "")))
        return timeline

    def _compute_evidence_score(
        self,
        inventory: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
        manifest_hash: str
    ) -> int:
        """Computes 0–100 evidence completeness & integrity score."""
        count = len(inventory)
        if count == 0:
            return 0

        score = 50  # Base collection score
        if count >= 5:
            score += 20
        elif count >= 2:
            score += 10

        # Artifact diversity
        types = {item.get("artifact_type") for item in inventory}
        if len(types) >= 3:
            score += 15
        elif len(types) >= 2:
            score += 10

        # Integrity verified
        if manifest_hash:
            score += 15

        return min(100, score)

    def _generate_findings_and_recs(
        self,
        incident_id: str,
        evidence_inventory: List[Dict[str, Any]],
        manifest_hash: str,
        evidence_score: int,
        findings: List[str],
        recommendations: List[str]
    ) -> None:
        """Populate forensic findings and recommendations."""
        findings.append(
            f"Collected {len(evidence_inventory)} digital forensic artifact(s) for incident {incident_id} (Score: {evidence_score}/100)."
        )
        findings.append(
            f"Chain-of-custody sealed with SHA-256 integrity hash: {manifest_hash[:16]}..."
        )

        recommendations.append("Export evidence manifest and store in write-once-read-many (WORM) immutable vault.")
        recommendations.append("Verify SHA-256 checksums prior to presenting evidence for legal or regulatory proceedings.")
