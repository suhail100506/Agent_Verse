import re
import json
import idna
import logging
import ipaddress
import urllib.parse
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class URLInspectionToolInput(BaseModel):
    """Input schema for URLInspectionTool."""
    url: str = Field(..., description="Absolute URL string to inspect for phishing, homograph attacks, and structural anomalies.")


class URLInspectionTool(BaseTool):
    name: str = "URL Inspection Tool"
    description: str = (
        "Parses URLs, checks SSL/HTTPS status, detects raw IP hosts, Punycode IDN homograph attacks (xn--), "
        "shortened links (bit.ly, tinyurl), embedded credentials, brand impersonation/typosquatting, and suspicious TLDs "
        "to compute a 0-100 URL risk score."
    )
    args_schema: Type[BaseModel] = URLInspectionToolInput

    def _run(self, url: str) -> str:
        """Execute URL structural threat analysis and risk scoring."""
        warnings: List[str] = []

        if not url or not isinstance(url, str) or not url.strip():
            return json.dumps({
                "success": False,
                "url_score": 0,
                "risk": "LOW",
                "dashboard": {"scheme": "", "domain": "", "https": False, "ip_url": False, "punycode": False, "shortened": False, "subdomains": 0, "query_parameters": 0},
                "findings": [],
                "recommendations": [],
                "error": "url argument must be a valid non-empty string."
            }, indent=2)

        try:
            clean_url = url.strip().strip('"').strip("'")
            if not clean_url.startswith(("http://", "https://")):
                clean_url = "http://" + clean_url

            parsed = urllib.parse.urlparse(clean_url)
            netloc = parsed.netloc or parsed.path.split("/")[0]

            # Extract User Credentials if present (e.g. user:pass@domain.com)
            has_credentials = "@" in netloc and ":" in netloc.split("@")[0]
            hostname = netloc.split("@")[-1].split(":")[0]

            # Subdomain & TLD Extraction
            subdomain, reg_domain, tld = self._extract_domain_parts(hostname)

            findings: List[str] = []
            recommendations: List[str] = []
            risk_score = 0

            # --- A. HTTPS & Encryption Analysis ---
            is_https = parsed.scheme.lower() == "https"
            if not is_https:
                risk_score += 15
                findings.append("HTTP protocol used without SSL/TLS encryption.")

            # --- B. IP Host Analysis ---
            is_ip_url = self._is_ip_address(hostname)
            if is_ip_url:
                risk_score += 25
                findings.append(f"URL uses a raw IP address host ('{hostname}') instead of a domain name.")

            # --- C. Punycode / IDN Homograph Detection ---
            is_punycode = hostname.lower().startswith("xn--") or "xn--" in hostname.lower()
            if is_punycode:
                risk_score += 20
                findings.append(f"Punycode / IDN homograph domain detected ('{hostname}').")

            # --- D. Shortened URL Detection ---
            shortener_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly"]
            is_shortened = any(short in reg_domain.lower() or short in hostname.lower() for short in shortener_domains)
            if is_shortened:
                risk_score += 10
                findings.append("URL shortening service detected.")

            # --- E. Embedded Credentials Check ---
            if has_credentials:
                risk_score += 20
                findings.append("Embedded user credentials detected in URL netloc.")

            # --- F. Subdomain Count Analysis ---
            subdomain_count = len(subdomain.split(".")) if subdomain else 0
            if subdomain_count >= 3:
                risk_score += 10
                findings.append(f"Excessive subdomains detected ({subdomain_count} subdomains).")

            # --- G. Suspicious TLD Check ---
            suspicious_tlds = ["zip", "mov", "top", "xyz", "work", "click", "download", "racing", "loan", "tk", "ml", "ga", "cf", "gq"]
            if tld.lower() in suspicious_tlds:
                risk_score += 15
                findings.append(f"High-risk top-level domain detected (.{tld}).")

            # --- H. Brand Impersonation / Typosquatting Check ---
            brand_impersonation = self._check_brand_impersonation(hostname, subdomain)
            if brand_impersonation:
                risk_score += 25
                findings.append(f"Brand impersonation / typosquatting indicator: Subdomain contains brand keyword '{brand_impersonation}'.")

            # --- I. Suspicious File Extensions & Encoding ---
            suspicious_exts = [".exe", ".scr", ".bat", ".vbs", ".ps1", ".apk", ".jar"]
            if any(parsed.path.lower().endswith(ext) for ext in suspicious_exts):
                risk_score += 20
                findings.append(f"Suspicious executable file download target in path ('{parsed.path}').")

            # 2. Finalize Risk Score & Risk Rating
            final_score = min(100, risk_score)

            if final_score >= 80:
                risk = "CRITICAL"
            elif final_score >= 60:
                risk = "HIGH"
            elif final_score >= 30:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # 3. Formulate Telemetry Dashboard
            query_params_count = len(urllib.parse.parse_qs(parsed.query))
            dashboard = {
                "scheme": parsed.scheme,
                "domain": reg_domain or hostname,
                "https": is_https,
                "ip_url": is_ip_url,
                "punycode": is_punycode,
                "shortened": is_shortened,
                "subdomains": subdomain_count,
                "query_parameters": query_params_count
            }

            # 4. Formulate Recommendations
            if risk in {"CRITICAL", "HIGH"}:
                recommendations.append("Do not open the URL.")
                recommendations.append("Expand shortened links using a URL expander before visiting.")
                recommendations.append("Verify destination domain with organization IT/Security.")
                recommendations.append("Block the URL in proxy/DNS filters if confirmed malicious.")
            elif risk == "MEDIUM":
                recommendations.append("Verify destination domain carefully before entering credentials.")
            else:
                recommendations.append("URL structural inspection passed baseline checks.")

            return json.dumps({
                "success": True,
                "url_score": final_score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing URLInspectionTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "url_score": 0,
                "risk": "LOW",
                "dashboard": {"scheme": "", "domain": "", "https": False, "ip_url": False, "punycode": False, "shortened": False, "subdomains": 0, "query_parameters": 0},
                "findings": [],
                "recommendations": [],
                "error": f"URL inspection failed: {str(e)}"
            }, indent=2)

    def _extract_domain_parts(self, hostname: str) -> tuple[str, str, str]:
        """Extract subdomain, registered domain, and TLD."""
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(hostname)
            return ext.subdomain, ext.registered_domain, ext.suffix

        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[:-2]), ".".join(parts[-2:]), parts[-1]
        return "", hostname, ""

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is a raw IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    def _check_brand_impersonation(self, hostname: str, subdomain: str) -> Optional[str]:
        """Detect well-known target brand keywords inside subdomains."""
        brands = ["paypal", "microsoft", "apple", "google", "chase", "wellsfargo", "amazon", "netflix", "bankofamerica"]
        sub_lower = subdomain.lower()
        host_lower = hostname.lower()

        for brand in brands:
            if brand in sub_lower and brand not in host_lower.split(".")[-2:]:
                return brand
        return None
