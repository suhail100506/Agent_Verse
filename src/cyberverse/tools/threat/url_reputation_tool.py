import os
import json
import base64
import logging
import ipaddress
from urllib.parse import urlparse, parse_qs
from typing import Type, Dict, Any, List, Optional
import requests
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

try:
    import validators
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class URLReputationToolInput(BaseModel):
    """Input schema for URLReputationTool."""
    url: str = Field(..., description="Target URL string to evaluate for phishing, malware, and security risks.")


class URLReputationTool(BaseTool):
    name: str = "URL Reputation Tool"
    description: str = (
        "Parses and evaluates URLs for security risks (insecure HTTP, raw IP hosts, private IP targets, excessive length), "
        "and queries Google Safe Browsing and VirusTotal APIs to detect malware, phishing, and social engineering threats."
    )
    args_schema: Type[BaseModel] = URLReputationToolInput

    def _run(self, url: str) -> str:
        """Execute URL validation, security heuristic checks, and API threat intelligence queries."""
        warnings: List[str] = []

        if not url or not isinstance(url, str):
            return json.dumps({
                "success": False,
                "url": str(url),
                "domain": "Unknown",
                "subdomain": "",
                "tld": "",
                "https": False,
                "is_ip_host": False,
                "safe_browsing": {"malicious": False, "threat_types": []},
                "virus_total": {"detections": 0, "reputation": 0},
                "risk": "LOW",
                "warnings": warnings,
                "error": "url argument must be a valid non-empty string."
            }, indent=2)

        clean_url = url.strip().strip('"').strip("'")
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "http://" + clean_url

        # 1. Parse URL & Extract Components
        parsed_data, parse_error = self._parse_url_components(clean_url, warnings)
        if parse_error:
            return json.dumps({
                "success": False,
                "url": clean_url,
                "domain": "Unknown",
                "subdomain": "",
                "tld": "",
                "https": False,
                "is_ip_host": False,
                "safe_browsing": {"malicious": False, "threat_types": []},
                "virus_total": {"detections": 0, "reputation": 0},
                "risk": "LOW",
                "warnings": warnings,
                "error": parse_error
            }, indent=2)

        # 2. Perform Heuristic Security Checks
        self._check_security_heuristics(parsed_data, warnings)

        # 3. Query Google Safe Browsing API v4
        sb_result = self._query_google_safe_browsing(clean_url, warnings)

        # 4. Query VirusTotal URL API v3
        vt_result = self._query_virustotal_url(clean_url, warnings)

        # 5. Calculate Risk Score & Rating
        risk_rating = self._calculate_risk_rating(sb_result, vt_result, warnings, parsed_data)

        return json.dumps({
            "success": True,
            "url": clean_url,
            "domain": parsed_data["domain"],
            "subdomain": parsed_data["subdomain"],
            "tld": parsed_data["tld"],
            "https": parsed_data["https"],
            "is_ip_host": parsed_data["is_ip_host"],
            "safe_browsing": sb_result,
            "virus_total": vt_result,
            "risk": risk_rating,
            "warnings": warnings,
            "error": None
        }, indent=2)

    def _parse_url_components(self, clean_url: str, warnings: List[str]) -> tuple[Dict[str, Any], Optional[str]]:
        """Parse URL scheme, host, domain, subdomain, TLD, and IP host status."""
        try:
            parsed = urlparse(clean_url)
            hostname = parsed.hostname or ""

            if not hostname:
                return {}, "Unable to extract valid hostname from URL."

            # Scheme check
            is_https = parsed.scheme.lower() == "https"

            # Hostname IP check
            is_ip = False
            try:
                ip_obj = ipaddress.ip_address(hostname)
                is_ip = True
                domain = str(ip_obj)
                subdomain = ""
                tld = ""

                if ip_obj.is_private or ip_obj.is_loopback:
                    warnings.append(f"URL targets internal/private IP address: {hostname}")
            except ValueError:
                is_ip = False

            if not is_ip:
                if HAS_TLDEXTRACT:
                    extracted = tldextract.extract(clean_url)
                    subdomain = extracted.subdomain
                    domain = extracted.registered_domain or hostname
                    tld = extracted.suffix
                else:
                    parts = hostname.split(".")
                    domain = hostname
                    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
                    tld = parts[-1] if len(parts) > 1 else ""

            return {
                "https": is_https,
                "hostname": hostname,
                "domain": domain,
                "subdomain": subdomain,
                "tld": tld,
                "is_ip_host": is_ip,
                "path": parsed.path,
                "query": parsed.query
            }, None
        except Exception as e:
            return {}, f"URL parsing failed: {str(e)}"

    def _check_security_heuristics(self, parsed_data: Dict[str, Any], warnings: List[str]) -> None:
        """Evaluate heuristic warning conditions."""
        if not parsed_data.get("https"):
            warnings.append("Insecure HTTP protocol used (missing HTTPS encryption).")

        if parsed_data.get("is_ip_host"):
            warnings.append(f"Host uses raw IP address instead of domain name: '{parsed_data.get('hostname')}'")

        if len(parsed_data.get("subdomain", "").split(".")) >= 3:
            warnings.append(f"Excessive subdomain nesting detected: '{parsed_data.get('subdomain')}'")

    def _query_google_safe_browsing(self, clean_url: str, warnings: List[str]) -> Dict[str, Any]:
        """Query Google Safe Browsing API v4."""
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        if not api_key:
            warnings.append("GOOGLE_SAFE_BROWSING_API_KEY environment variable is not set. Safe Browsing lookup skipped.")
            return {"malicious": False, "threat_types": []}

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {
                "clientId": "CyberVerse",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": clean_url}]
            }
        }

        try:
            resp = requests.post(endpoint, json=payload, timeout=10)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                if matches:
                    threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
                    return {"malicious": True, "threat_types": threat_types}
                return {"malicious": False, "threat_types": []}
            else:
                warnings.append(f"Google Safe Browsing returned HTTP status {resp.status_code}.")
                return {"malicious": False, "threat_types": []}
        except Exception as e:
            logger.warning(f"Google Safe Browsing query failed: {e}")
            warnings.append(f"Google Safe Browsing API query failed: {str(e)}")
            return {"malicious": False, "threat_types": []}

    def _query_virustotal_url(self, clean_url: str, warnings: List[str]) -> Dict[str, Any]:
        """Query VirusTotal URL API v3."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        if not api_key:
            warnings.append("VIRUSTOTAL_API_KEY environment variable is not set. VirusTotal URL lookup skipped.")
            return {"detections": 0, "reputation": 0}

        try:
            # Generate Base64 URL Identifier (urlsafe, no padding '=')
            url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {"x-apikey": api_key, "Accept": "application/json"}

            resp = requests.get(endpoint, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                reputation = data.get("reputation", 0)
                return {"detections": malicious_count, "reputation": reputation}
            elif resp.status_code == 404:
                warnings.append("URL hash not found in VirusTotal database.")
                return {"detections": 0, "reputation": 0}
            else:
                warnings.append(f"VirusTotal URL API returned HTTP status {resp.status_code}.")
                return {"detections": 0, "reputation": 0}
        except Exception as e:
            logger.warning(f"VirusTotal URL query failed: {e}")
            warnings.append(f"VirusTotal URL API query failed: {str(e)}")
            return {"detections": 0, "reputation": 0}

    def _calculate_risk_rating(
        self,
        sb_result: Dict[str, Any],
        vt_result: Dict[str, Any],
        warnings: List[str],
        parsed_data: Dict[str, Any]
    ) -> str:
        """Compute overall risk: CRITICAL, HIGH, MEDIUM, LOW."""
        if sb_result.get("malicious") or vt_result.get("detections", 0) >= 5:
            return "CRITICAL"
        elif vt_result.get("detections", 0) >= 1:
            return "HIGH"

        # Count security warnings
        heuristic_warnings_count = len([
            w for w in warnings
            if "Insecure HTTP" in w or "raw IP address" in w or "internal/private IP" in w or "Excessive subdomain" in w
        ])

        if parsed_data.get("is_ip_host") or heuristic_warnings_count >= 2:
            return "MEDIUM"

        return "LOW"
