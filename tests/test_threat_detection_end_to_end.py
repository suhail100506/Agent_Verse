import os
import json
import unittest
from cyberverse.tools.threat.ip_reputation_tool import IPReputationTool
from cyberverse.tools.threat.url_reputation_tool import URLReputationTool
from cyberverse.tools.threat.dns_analysis_tool import DNSAnalysisTool
from cyberverse.tools.threat.ioc_analysis_tool import IOCAnalysisTool
from cyberverse.tools.threat.threat_risk_tool import ThreatRiskTool

class TestThreatDetectionEndToEnd(unittest.TestCase):
    def setUp(self):
        self.ip_tool = IPReputationTool()
        self.url_tool = URLReputationTool()
        self.dns_tool = DNSAnalysisTool()
        self.ioc_tool = IOCAnalysisTool()
        self.risk_tool = ThreatRiskTool()

    def test_end_to_end_threat_detection_workflow(self):
        """End-to-End integration test for Threat Detection Specialist workflow."""
        test_payload = """
        # Incident Report - Threat Feed Alert #94812
        Threat Level: CRITICAL
        Timestamp: 2026-07-29T21:45:00Z
        Target Domain: google.com
        C2 Callback Server: http://192.168.1.1/admin/gateway.php
        Public Host IP: 8.8.8.8
        Exposed S3 Bucket: https://data-exfil-leak.s3.amazonaws.com/credentials.tar.gz

        Known Malicious File Hashes:
        MD5: 392e110c59298dccfa1862db3173df83
        SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

        Vulnerability & Attack Vectors:
        - Exploited Vulnerability: CVE-2023-38606 (Apple Kernel Vulnerability)
        - MITRE ATT&CK Technique: T1059.001 (Command and Scripting Interpreter: PowerShell)
        - MITRE ATT&CK Group: G0007 (APT28)
        - Contact Email: soc-alert@cybercorp.com
        """

        print("\n=== STEP 1: Executing IOCAnalysisTool ===")
        ioc_res_str = self.ioc_tool._run(text=test_payload)
        ioc_res = json.loads(ioc_res_str)
        self.assertTrue(ioc_res["success"])
        self.assertGreaterEqual(ioc_res["ioc_count"], 6)
        print(f"Extracted Total IOCs: {ioc_res['ioc_count']}")
        print(f"IOC Summary Counts: {json.dumps(ioc_res['summary'])}")

        print("\n=== STEP 2: Executing IPReputationTool ===")
        ip_res_str = self.ip_tool._run(ip_address="8.8.8.8")
        ip_res = json.loads(ip_res_str)
        self.assertTrue(ip_res["success"])
        print(f"IP Target: {ip_res['ip']}, Public: {ip_res['is_public']}, Risk: {ip_res['risk']}")

        print("\n=== STEP 3: Executing URLReputationTool ===")
        url_res_str = self.url_tool._run(url="http://192.168.1.1/admin/gateway.php")
        url_res = json.loads(url_res_str)
        self.assertTrue(url_res["success"])
        print(f"URL Target: {url_res['url']}, IP Host: {url_res['is_ip_host']}, Risk: {url_res['risk']}")

        print("\n=== STEP 4: Executing DNSAnalysisTool ===")
        dns_res_str = self.dns_tool._run(domain="google.com")
        dns_res = json.loads(dns_res_str)
        self.assertTrue(dns_res["success"])
        print(f"Domain Target: {dns_res['domain']}, Risk: {dns_res['risk']}")
        print(f"DMARC Policy: {dns_res['email_security']['dmarc']['policy']}")

        print("\n=== STEP 5: Executing ThreatRiskTool Synthesis ===")
        risk_res_str = self.risk_tool._run(
            ip_reputation=ip_res_str,
            url_reputation=url_res_str,
            dns_analysis=dns_res_str,
            ioc_analysis=ioc_res_str
        )
        risk_res = json.loads(risk_res_str)
        self.assertTrue(risk_res["success"])
        print(f"Overall Risk: {risk_res['overall_risk']}")
        print(f"Threat Score: {risk_res['threat_score']}/100")
        print(f"Active Threat Flag: {risk_res['active_threat']}")

        print("\n========================================================")
        print("FINAL ENTERPRISE THREAT INTELLIGENCE REPORT JSON")
        print("========================================================")
        final_report = {
            "specialist": "Threat Detection Specialist",
            "overall_risk": risk_res["overall_risk"],
            "threat_score": risk_res["threat_score"],
            "confidence": risk_res["confidence"],
            "active_threat": risk_res["active_threat"],
            "dashboard": risk_res["dashboard"],
            "evidence": risk_res["evidence"],
            "recommendations": risk_res["recommendations"],
            "executive_summary": risk_res["executive_summary"]
        }
        print(json.dumps(final_report, indent=2))

if __name__ == "__main__":
    unittest.main()
