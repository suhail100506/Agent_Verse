import os
import json
import unittest
from unittest.mock import patch, MagicMock
from cyberverse.tools.malware.virus_total_tool import VirusTotalTool

class TestVirusTotalToolIntegration(unittest.TestCase):
    def setUp(self):
        self.tool = VirusTotalTool()
        self.eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        self.clean_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # Empty file SHA256
        self.unknown_hash = "0000000000000000000000000000000000000000000000000000000000000000"

    def test_missing_api_key(self):
        """Scenario 5: Missing API Key"""
        with patch.dict(os.environ, {}, clear=True):
            res_str = self.tool._run(sha256=self.eicar_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 5: Missing API Key ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertFalse(res["file_found"])
            self.assertIn("VIRUSTOTAL_API_KEY environment variable is not set", res["warnings"][0])

    @patch("requests.get")
    def test_valid_malware_hash(self, mock_get):
        """Scenario 1: Valid Malware Hash Response Parsing"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 58,
                        "suspicious": 2,
                        "harmless": 1,
                        "undetected": 11
                    },
                    "last_analysis_results": {
                        "Microsoft": {"category": "malicious", "result": "Trojan:Win32/Emotet"},
                        "Kaspersky": {"category": "malicious", "result": "HEUR:Trojan.Win32.Emotet"},
                        "Sophos": {"category": "harmless", "result": "clean"}
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "Emotet",
                        "popular_threat_category": [{"value": "trojan"}]
                    },
                    "reputation": -25,
                    "total_votes": {
                        "harmless": 1,
                        "malicious": 18
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_test_api_key"}):
            res_str = self.tool._run(sha256=self.eicar_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 1: Valid Malware Hash ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertTrue(res["file_found"])
            self.assertEqual(res["detection_ratio"], "60/72")
            self.assertEqual(res["risk"], "CRITICAL")
            self.assertEqual(res["popular_threat"], "Emotet")
            self.assertEqual(len(res["vendors"]), 2)
            self.assertEqual(res["community"]["reputation"], -25)

    @patch("requests.get")
    def test_clean_file_hash(self, mock_get):
        """Scenario 2: Clean File Hash Response Parsing"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 2
                    },
                    "last_analysis_results": {
                        "Microsoft": {"category": "harmless", "result": "clean"},
                        "Kaspersky": {"category": "harmless", "result": "clean"}
                    },
                    "reputation": 100,
                    "total_votes": {"harmless": 25, "malicious": 0}
                }
            }
        }
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_test_api_key"}):
            res_str = self.tool._run(sha256=self.clean_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 2: Clean File Hash ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertTrue(res["file_found"])
            self.assertEqual(res["detection_ratio"], "0/72")
            self.assertEqual(res["risk"], "LOW")
            self.assertEqual(len(res["vendors"]), 0)

    @patch("requests.get")
    def test_unknown_hash_404(self, mock_get):
        """Scenario 3: Unknown Hash (HTTP 404)"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_test_api_key"}):
            res_str = self.tool._run(sha256=self.unknown_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 3: Unknown Hash (HTTP 404) ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertFalse(res["file_found"])
            self.assertIn("not found in VirusTotal database", res["warnings"][0])

    @patch("requests.get")
    def test_invalid_api_key_401(self, mock_get):
        """Scenario 4: Invalid API Key (HTTP 401)"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "invalid_key"}):
            res_str = self.tool._run(sha256=self.eicar_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 4: Invalid API Key (HTTP 401) ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertFalse(res["file_found"])
            self.assertIn("invalid or unauthorized", res["warnings"][0])

    @patch("requests.get")
    def test_rate_limit_429(self, mock_get):
        """Scenario 6: Rate Limit Handling (HTTP 429)"""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "dummy_test_api_key"}):
            res_str = self.tool._run(sha256=self.eicar_hash)
            res = json.loads(res_str)
            print("\n=== Scenario 6: Rate Limit Handling (HTTP 429) ===")
            print(json.dumps(res, indent=2))
            self.assertTrue(res["success"])
            self.assertFalse(res["file_found"])
            self.assertIn("rate limit exceeded", res["warnings"][0])

if __name__ == "__main__":
    unittest.main()
