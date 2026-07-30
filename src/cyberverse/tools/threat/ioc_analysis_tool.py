import os
import re
import json
import logging
import ipaddress
from urllib.parse import urlparse
from typing import Type, Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Compiled Regular Expressions for High-Efficiency Match Engine
RE_IPV4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
RE_IPV6 = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b')
RE_URL = re.compile(r'\bhttps?://[^\s<>"]+|www\.[^\s<>"]+\b', re.IGNORECASE)
RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
RE_DOMAIN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
RE_SHA512 = re.compile(r'\b[a-fA-F0-9]{128}\b')

RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
RE_MITRE_TECH = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
RE_MITRE_SW = re.compile(r'\bS\d{4}\b')
RE_MITRE_GRP = re.compile(r'\bG\d{4}\b')

RE_S3 = re.compile(r'\b[a-zA-Z0-9.\-_]+\.s3\.amazonaws\.com\b|\bs3://[a-zA-Z0-9.\-_]+\b', re.IGNORECASE)
RE_AZURE_BLOB = re.compile(r'\b[a-zA-Z0-9.\-_]+\.blob\.core\.windows\.net\b', re.IGNORECASE)
RE_GCS = re.compile(r'\bstorage\.googleapis\.com/[a-zA-Z0-9.\-_]+\b', re.IGNORECASE)

RE_BTC = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
RE_ONION = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.IGNORECASE)


class IOCAnalysisToolInput(BaseModel):
    """Input schema for IOCAnalysisTool."""
    text: str = Field(..., description="Free-form text content, logs, SIEM alerts, email bodies, or threat feeds to parse for IOC indicators.")


class IOCAnalysisTool(BaseTool):
    name: str = "IOC Analysis Tool"
    description: str = (
        "Extracts, validates, deduplicates, and categorizes Indicators of Compromise (IPv4, IPv6, Domains, URLs, Emails, "
        "MD5/SHA1/SHA256/SHA512 hashes, CVEs, MITRE ATT&CK technique IDs, Cloud storage URLs, Bitcoin wallets, Tor onion links) "
        "from raw text, logs, or incident reports."
    )
    args_schema: Type[BaseModel] = IOCAnalysisToolInput

    def _run(self, text: str) -> str:
        """Execute IOC extraction and categorization engine."""
        warnings: List[str] = []

        if not text or not isinstance(text, str):
            return json.dumps({
                "success": False,
                "ioc_count": 0,
                "summary": {"ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0, "emails": 0, "md5": 0, "sha1": 0, "sha256": 0, "sha512": 0, "cves": 0, "mitre": 0},
                "iocs": [],
                "findings": [],
                "warnings": warnings,
                "error": "text argument must be a valid non-empty string."
            }, indent=2)

        try:
            iocs: List[Dict[str, Any]] = []
            seen_values: Set[str] = set()

            # 1. Extract Hashes (Order matters: SHA512 -> SHA256 -> SHA1 -> MD5 to prevent sub-string matching)
            sha512_matches = self._extract_regex(text, RE_SHA512, "SHA512", "HIGH", iocs, seen_values)
            sha256_matches = self._extract_regex(text, RE_SHA256, "SHA256", "HIGH", iocs, seen_values)
            sha1_matches = self._extract_regex(text, RE_SHA1, "SHA1", "HIGH", iocs, seen_values)
            md5_matches = self._extract_regex(text, RE_MD5, "MD5", "HIGH", iocs, seen_values)

            # 2. Extract Network Indicators
            ipv4_matches = self._extract_ipv4(text, iocs, seen_values)
            ipv6_matches = self._extract_ipv6(text, iocs, seen_values)
            url_matches = self._extract_urls(text, iocs, seen_values)
            email_matches = self._extract_regex(text, RE_EMAIL, "Email", "MEDIUM", iocs, seen_values)
            domain_matches = self._extract_domains(text, iocs, seen_values)

            # 3. Extract Threat Intelligence (CVEs & MITRE ATT&CK)
            cve_matches = self._extract_regex(text, RE_CVE, "CVE", "HIGH", iocs, seen_values)
            mitre_matches = (
                self._extract_regex(text, RE_MITRE_TECH, "MITRE ATT&CK", "MEDIUM", iocs, seen_values) +
                self._extract_regex(text, RE_MITRE_SW, "MITRE ATT&CK", "MEDIUM", iocs, seen_values) +
                self._extract_regex(text, RE_MITRE_GRP, "MITRE ATT&CK", "MEDIUM", iocs, seen_values)
            )

            # 4. Extract Cloud Storage & Optional Indicators
            s3_matches = self._extract_regex(text, RE_S3, "AWS S3 URL", "HIGH", iocs, seen_values)
            azure_matches = self._extract_regex(text, RE_AZURE_BLOB, "Azure Blob URL", "HIGH", iocs, seen_values)
            gcs_matches = self._extract_regex(text, RE_GCS, "Google Cloud Storage URL", "HIGH", iocs, seen_values)
            btc_matches = self._extract_regex(text, RE_BTC, "Bitcoin Address", "MEDIUM", iocs, seen_values)
            onion_matches = self._extract_regex(text, RE_ONION, "Tor Domain", "HIGH", iocs, seen_values)

            # 5. Formulate Telemetry Summary Counts
            summary = {
                "ipv4": len(ipv4_matches),
                "ipv6": len(ipv6_matches),
                "domains": len(domain_matches),
                "urls": len(url_matches),
                "emails": len(email_matches),
                "md5": len(md5_matches),
                "sha1": len(sha1_matches),
                "sha256": len(sha256_matches),
                "sha512": len(sha512_matches),
                "cves": len(cve_matches),
                "mitre": len(mitre_matches)
            }

            # 6. Formulate Threat Context Findings
            findings = self._generate_findings(summary, iocs)

            return json.dumps({
                "success": True,
                "ioc_count": len(iocs),
                "summary": summary,
                "iocs": iocs,
                "findings": findings,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing IOCAnalysisTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "ioc_count": 0,
                "summary": {"ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0, "emails": 0, "md5": 0, "sha1": 0, "sha256": 0, "sha512": 0, "cves": 0, "mitre": 0},
                "iocs": [],
                "findings": [],
                "warnings": warnings,
                "error": f"IOC extraction failed: {str(e)}"
            }, indent=2)

    def _extract_ipv4(self, text: str, iocs: List[Dict[str, Any]], seen: Set[str]) -> List[str]:
        """Extract and validate IPv4 addresses."""
        matches = []
        for raw in RE_IPV4.findall(text):
            try:
                ip_obj = ipaddress.IPv4Address(raw)
                val = str(ip_obj)
                if val not in seen:
                    seen.add(val)
                    matches.append(val)
                    iocs.append({"type": "IPv4", "value": val, "confidence": "HIGH"})
            except ValueError:
                continue
        return matches

    def _extract_ipv6(self, text: str, iocs: List[Dict[str, Any]], seen: Set[str]) -> List[str]:
        """Extract and validate IPv6 addresses."""
        matches = []
        for raw in RE_IPV6.findall(text):
            try:
                ip_obj = ipaddress.IPv6Address(raw)
                val = str(ip_obj)
                if val not in seen:
                    seen.add(val)
                    matches.append(val)
                    iocs.append({"type": "IPv6", "value": val, "confidence": "HIGH"})
            except ValueError:
                continue
        return matches

    def _extract_urls(self, text: str, iocs: List[Dict[str, Any]], seen: Set[str]) -> List[str]:
        """Extract and validate URLs."""
        matches = []
        for raw in RE_URL.findall(text):
            clean = raw.strip().rstrip(".,;:)'\"")
            if clean not in seen and len(clean) > 8:
                seen.add(clean)
                matches.append(clean)
                iocs.append({"type": "URL", "value": clean, "confidence": "HIGH"})
        return matches

    def _extract_domains(self, text: str, iocs: List[Dict[str, Any]], seen: Set[str]) -> List[str]:
        """Extract valid domain names avoiding sub-matches inside URLs or emails."""
        matches = []
        for raw in RE_DOMAIN.findall(text):
            clean = raw.strip().lower().rstrip(".")
            if clean in seen:
                continue
            # Skip if common file extension or IP
            if clean.endswith((".py", ".json", ".txt", ".png", ".jpg", ".exe", ".dll", ".tmp", ".md")):
                continue
            try:
                # Confirm not an IP address
                ipaddress.ip_address(clean)
                continue
            except ValueError:
                pass

            seen.add(clean)
            matches.append(clean)
            iocs.append({"type": "Domain", "value": clean, "confidence": "MEDIUM"})
        return matches

    def _extract_regex(
        self,
        text: str,
        pattern: re.Pattern,
        ioc_type: str,
        confidence: str,
        iocs: List[Dict[str, Any]],
        seen: Set[str]
    ) -> List[str]:
        """Generic regex extraction helper."""
        matches = []
        for raw in pattern.findall(text):
            val = str(raw).strip()
            if val and val not in seen:
                seen.add(val)
                matches.append(val)
                iocs.append({"type": ioc_type, "value": val, "confidence": confidence})
        return matches

    def _generate_findings(self, summary: Dict[str, int], iocs: List[Dict[str, Any]]) -> List[str]:
        """Generate high-level context findings."""
        findings = []
        total = sum(summary.values())
        if total == 0:
            return ["No Indicators of Compromise detected in input text."]

        findings.append(f"Extracted {total} total Indicators of Compromise.")

        total_hashes = summary["md5"] + summary["sha1"] + summary["sha256"] + summary["sha512"]
        if total_hashes > 0:
            findings.append(f"Multiple cryptographic file hashes detected ({total_hashes} hashes found).")

        if summary["ipv4"] + summary["ipv6"] > 0:
            findings.append(f"Public/Internal network IP addresses identified ({summary['ipv4']} IPv4, {summary['ipv6']} IPv6).")

        if summary["urls"] > 0:
            findings.append(f"Target URLs extracted ({summary['urls']} URLs found).")

        if summary["cves"] > 0:
            findings.append(f"Known CVE vulnerability identifiers detected ({summary['cves']} CVEs found).")

        if summary["mitre"] > 0:
            findings.append(f"MITRE ATT&CK techniques or software references identified ({summary['mitre']} references).")

        return findings
