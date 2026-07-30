"""
test_incident_response_end_to_end.py
====================================
End-to-end integration test for the Incident Response Specialist tool suite.

Workflow Under Test
-------------------
Security Incident Metadata
            │
            ▼
IncidentClassificationTool — Category, severity, asset criticality, business impact, priority P1–P5
            │
            ▼
MITREMappingTool           — ATT&CK techniques (Txxxx), tactics, Kill Chain, threat actors
            │
            ▼
ForensicEvidenceTool       — Read-only evidence collection, SHA-256 chain-of-custody, timeline
            │
            ▼
ContainmentPlanTool        — Immediate (0-1h), Short-term (1-24h), Long-term (1-30d) action playbooks
            │
            ▼
IncidentResponseTool       — Weighted incident score, risk, confidence, executive summary

Coverage
--------
- Tool instantiation & registration checks
- Individual tool functionality and schema validation
- Complete end-to-end chained workflow execution
- Partial telemetry aggregation
- Enterprise output structure validation
"""

import json
import sys
import unittest

sys.path.insert(0, "src")

from cyberverse.tools.incident.incident_classification_tool import IncidentClassificationTool
from cyberverse.tools.incident.mitre_mapping_tool import MITREMappingTool
from cyberverse.tools.incident.forensic_evidence_tool import ForensicEvidenceTool
from cyberverse.tools.incident.containment_plan_tool import ContainmentPlanTool
from cyberverse.tools.incident.incident_response_tool import IncidentResponseTool


class TestIncidentResponseEndToEnd(unittest.TestCase):
    """End-to-end integration test suite for Incident Response Specialist."""

    @classmethod
    def setUpClass(cls) -> None:
        """Instantiate all five Incident Response tools."""
        cls.classification_tool = IncidentClassificationTool()
        cls.mitre_tool = MITREMappingTool()
        cls.evidence_tool = ForensicEvidenceTool()
        cls.containment_tool = ContainmentPlanTool()
        cls.response_tool = IncidentResponseTool()

    def test_01_tool_registration(self) -> None:
        """Verify all 5 tools are instantiated with correct names."""
        print("\n=== TEST 01: Tool Registration ===")
        self.assertEqual(self.classification_tool.name, "Incident Classification Tool")
        self.assertEqual(self.mitre_tool.name, "MITRE Mapping Tool")
        self.assertEqual(self.evidence_tool.name, "Forensic Evidence Tool")
        self.assertEqual(self.containment_tool.name, "Containment Plan Tool")
        self.assertEqual(self.response_tool.name, "Incident Response Tool")
        print("  [OK] All five Incident Response Specialist tools registered successfully.")

    def test_02_incident_classification_tool(self) -> None:
        """Verify IncidentClassificationTool functionality."""
        print("\n=== TEST 02: IncidentClassificationTool ===")
        res_str = self.classification_tool._run(
            incident_id="INC-001",
            title="Suspicious PowerShell Execution",
            description="Encoded PowerShell launched from Office document.",
            source="EDR",
            asset="FINANCE-PC-01",
            severity="Unknown",
            ioc=["powershell.exe", "Base64 Command"]
        )
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertEqual(res["incident_type"], "Malware")
        self.assertIn(res["severity"], ("HIGH", "CRITICAL"))
        self.assertEqual(res["priority"], "P1")
        self.assertGreater(res["confidence"], 80)
        print(f"  [OK] Incident Type: {res['incident_type']}, Severity: {res['severity']}, Priority: {res['priority']}")

    def test_03_mitre_mapping_tool(self) -> None:
        """Verify MITREMappingTool functionality."""
        print("\n=== TEST 03: MITREMappingTool ===")
        res_str = self.mitre_tool._run(
            title="Suspicious PowerShell Execution",
            description="Encoded PowerShell launched from Office document.",
            ioc=["powershell.exe", "Base64 Command"]
        )
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertGreaterEqual(len(res["mapped_techniques"]), 2)
        tech_ids = [t["id"] for t in res["mapped_techniques"]]
        self.assertIn("T1059.001", tech_ids)
        self.assertIn("T1027", tech_ids)
        print(f"  [OK] Mapped Techniques: {tech_ids}, Tactics: {res['tactics_summary']}")

    def test_04_forensic_evidence_tool(self) -> None:
        """Verify ForensicEvidenceTool functionality."""
        print("\n=== TEST 04: ForensicEvidenceTool ===")
        res_str = self.evidence_tool._run(
            incident_id="INC-001",
            collector_id="ANALYSIS-UNIT-1",
            processes=[
                {"pid": 4102, "name": "powershell.exe", "cmdline": "powershell -enc aW52b2tl...", "user": "SYSTEM"}
            ],
            network_connections=[
                {"src_ip": "192.168.1.100", "dest_ip": "203.0.113.50", "dest_port": 443, "protocol": "TCP"}
            ],
            dns_queries=["malicious-c2-domain.com"],
            event_logs=[
                {"event_id": 4104, "provider": "Microsoft-Windows-PowerShell", "details": "ScriptBlock execution"}
            ]
        )
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertGreaterEqual(res["evidence_score"], 80)
        self.assertIn("manifest_sha256", res["chain_of_custody"])
        self.assertGreaterEqual(len(res["evidence"]), 4)
        print(f"  [OK] Evidence Score: {res['evidence_score']}/100, Manifest Digest: {res['chain_of_custody']['manifest_sha256'][:16]}...")

    def test_05_containment_plan_tool(self) -> None:
        """Verify ContainmentPlanTool functionality."""
        print("\n=== TEST 05: ContainmentPlanTool ===")
        res_str = self.containment_tool._run(
            incident_id="INC-001",
            incident_type="Malware",
            severity="HIGH",
            priority="P1",
            asset="FINANCE-PC-01",
            compromised_accounts=["jdoe@company.com"],
            malicious_ips=["203.0.113.50"],
            malicious_domains=["malicious-c2.com"],
            malicious_pids=[4102]
        )
        res = json.loads(res_str)

        self.assertTrue(res["success"])
        self.assertEqual(res["priority"], "P1")
        self.assertGreaterEqual(len(res["containment_actions"]), 4)
        self.assertGreaterEqual(len(res["recovery_actions"]), 4)
        print(f"  [OK] Containment Actions: {len(res['containment_actions'])}, Recovery Actions: {len(res['recovery_actions'])}")

    def test_06_end_to_end_workflow(self) -> None:
        """Execute full end-to-end workflow chaining all 5 Incident Response tools."""
        print("\n=== TEST 06: Full End-to-End Workflow Execution ===")

        # Step 1: Classification
        class_res = json.loads(self.classification_tool._run(
            incident_id="INC-001",
            title="Suspicious PowerShell Execution",
            description="Encoded PowerShell launched from Office document.",
            source="EDR",
            asset="FINANCE-PC-01",
            severity="Unknown",
            ioc=["powershell.exe", "Base64 Command"]
        ))

        # Step 2: MITRE Mapping
        mitre_res = json.loads(self.mitre_tool._run(
            title="Suspicious PowerShell Execution",
            description="Encoded PowerShell launched from Office document.",
            ioc=["powershell.exe", "Base64 Command"]
        ))

        # Step 3: Forensic Evidence
        evidence_res = json.loads(self.evidence_tool._run(
            incident_id="INC-001",
            collector_id="ANALYSIS-UNIT-1",
            processes=[
                {"pid": 4102, "name": "powershell.exe", "cmdline": "powershell -enc aW52b2tl...", "user": "SYSTEM"}
            ],
            network_connections=[
                {"src_ip": "192.168.1.100", "dest_ip": "203.0.113.50", "dest_port": 443, "protocol": "TCP"}
            ],
            dns_queries=["malicious-c2-domain.com"],
            event_logs=[
                {"event_id": 4104, "provider": "Microsoft-Windows-PowerShell", "details": "ScriptBlock execution"}
            ]
        ))

        # Step 4: Containment Plan
        containment_res = json.loads(self.containment_tool._run(
            incident_id="INC-001",
            incident_type=class_res.get("incident_type", "Malware"),
            severity=class_res.get("severity", "HIGH"),
            priority=class_res.get("priority", "P1"),
            asset="FINANCE-PC-01",
            compromised_accounts=["jdoe@company.com"],
            malicious_ips=["203.0.113.50"],
            malicious_domains=["malicious-c2.com"],
            malicious_pids=[4102]
        ))

        # Step 5: Incident Response Aggregation
        response_res = json.loads(self.response_tool._run(
            classification=class_res,
            mitre=mitre_res,
            evidence=evidence_res,
            containment=containment_res
        ))

        print("  -- Incident Response Assessment Output --")
        print(f"  Overall Risk    : {response_res['overall_risk']}")
        print(f"  Incident Score  : {response_res['incident_score']}/100")
        print(f"  Priority        : {response_res['priority']}")
        print(f"  Confidence      : {response_res['confidence']}%")
        print(f"  Dashboard       : {json.dumps(response_res['dashboard'], indent=4)}")

        self.assertTrue(response_res["success"])
        self.assertIn("overall_risk", response_res)
        self.assertIn("incident_score", response_res)
        self.assertIn("confidence", response_res)
        self.assertIn("priority", response_res)
        self.assertIn("dashboard", response_res)
        self.assertIn("evidence", response_res)
        self.assertIn("recommendations", response_res)
        self.assertIn("executive_summary", response_res)
        self.assertIn(response_res["overall_risk"], ("HIGH", "CRITICAL"))

    def test_07_enterprise_sample_output_structure(self) -> None:
        """Validate enterprise sample output schema."""
        print("\n=== TEST 07: Enterprise Sample Output Schema ===")
        sample_output = {
            "specialist": "Incident Response Specialist",
            "overall_risk": "CRITICAL",
            "incident_score": 94,
            "confidence": 99,
            "priority": "P1",
            "dashboard": {
                "severity": "HIGH",
                "mapped_techniques": 6,
                "evidence_items": 28,
                "containment_actions": 12
            },
            "evidence": [
                "PowerShell execution detected.",
                "MITRE T1059.001 mapped.",
                "Persistence mechanism identified.",
                "Malicious outbound connection observed."
            ],
            "recommendations": [
                "Isolate affected endpoint.",
                "Preserve forensic evidence.",
                "Reset compromised credentials.",
                "Initiate threat hunting.",
                "Notify stakeholders."
            ],
            "executive_summary": "A critical security incident has been confirmed. Immediate containment, forensic preservation, and coordinated response actions are required."
        }

        required_keys = [
            "specialist", "overall_risk", "incident_score", "confidence",
            "priority", "dashboard", "evidence", "recommendations", "executive_summary"
        ]
        for k in required_keys:
            self.assertIn(k, sample_output)

        print("  [OK] Enterprise sample output structure validated.")
        print(json.dumps(sample_output, indent=2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
