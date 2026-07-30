import re
import ssl
import json
import socket
import logging
from datetime import datetime, timezone
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DomainReputationToolInput(BaseModel):
    """Input schema for DomainReputationTool."""
    domain: str = Field(..., description="Target domain name to analyze (e.g. example.com).")


class DomainReputationTool(BaseTool):
    name: str = "Domain Reputation Tool"
    description: str = (
        "Evaluates domain WHOIS creation age, registrar metadata, DNS health (MX, TXT/SPF/DMARC), SSL/TLS certificate validity, "
        "high-risk TLDs, and typosquatting indicators to compute a 0-100 Domain Trust Score and risk level."
    )
    args_schema: Type[BaseModel] = DomainReputationToolInput

    def _run(self, domain: str) -> str:
        """Execute domain reputation evaluation and trust scoring."""
        warnings: List[str] = []

        if not domain or not isinstance(domain, str) or not domain.strip():
            return json.dumps({
                "success": False,
                "trust_score": 0,
                "risk": "CRITICAL",
                "dashboard": {"domain": "", "age_days": 0, "registrar": "Unknown", "ssl_valid": False, "spf": False, "dkim": False, "dmarc": False, "trust_score": 0},
                "findings": [],
                "recommendations": [],
                "error": "domain argument must be a valid non-empty string."
            }, indent=2)

        try:
            clean_domain = self._normalize_domain(domain)
            findings: List[str] = []
            recommendations: List[str] = []
            risk_penalty = 0

            # --- A. WHOIS & Domain Age Analysis ---
            whois_info = self._get_whois_data(clean_domain, warnings)
            age_days = whois_info.get("age_days")
            registrar = whois_info.get("registrar", "Unknown")

            if age_days is None:
                risk_penalty += 20
                findings.append("WHOIS registration data unavailable or privacy-protected.")
            elif age_days < 30:
                risk_penalty += 25
                findings.append(f"Newly registered domain detected ({age_days} days old). High risk for phishing/malware.")
            elif age_days < 90:
                risk_penalty += 15
                findings.append(f"Young domain registration ({age_days} days old).")

            # --- B. DNS Health & Email Security (SPF / DMARC) ---
            dns_info = self._get_dns_health(clean_domain, warnings)
            has_spf = dns_info.get("spf", False)
            has_dmarc = dns_info.get("dmarc", False)
            has_mx = dns_info.get("mx", False)

            if not has_spf:
                risk_penalty += 10
                findings.append("Missing SPF record in DNS TXT records.")
            if not has_dmarc:
                risk_penalty += 10
                findings.append("Missing DMARC policy record in DNS TXT records.")
            if not has_mx:
                findings.append("No MX mail exchange servers found for domain.")

            # --- C. SSL/TLS Certificate Inspection ---
            ssl_info = self._get_ssl_info(clean_domain, warnings)
            ssl_valid = ssl_info.get("valid", False)
            if not ssl_valid:
                risk_penalty += 20
                if ssl_info.get("reason"):
                    findings.append(f"SSL/TLS Certificate issue: {ssl_info.get('reason')}")
                else:
                    findings.append("SSL/TLS certificate invalid, expired, or missing.")

            # --- D. Domain Intelligence & Typosquatting ---
            ext_tld = self._get_tld(clean_domain)
            high_risk_tlds = ["zip", "mov", "top", "xyz", "work", "click", "download", "racing", "loan", "tk", "ml", "ga", "cf", "gq"]
            if ext_tld.lower() in high_risk_tlds:
                risk_penalty += 15
                findings.append(f"High-risk top-level domain detected (.{ext_tld}).")

            brand_typosquat = self._check_typosquatting(clean_domain)
            if brand_typosquat:
                risk_penalty += 25
                findings.append(f"Potential typosquatting / brand impersonation: Domain contains target brand keyword '{brand_typosquat}'.")

            # 2. Compute Final Domain Trust Score & Risk Level
            trust_score = max(0, min(100, 100 - risk_penalty))

            if trust_score < 40:
                risk = "CRITICAL"
            elif trust_score < 60:
                risk = "HIGH"
            elif trust_score < 80:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # 3. Formulate Telemetry Dashboard
            dashboard = {
                "domain": clean_domain,
                "age_days": age_days if age_days is not None else 0,
                "registrar": registrar,
                "ssl_valid": ssl_valid,
                "spf": has_spf,
                "dkim": dns_info.get("dkim", False),
                "dmarc": has_dmarc,
                "trust_score": trust_score
            }

            # 4. Formulate Recommendations
            if risk in {"CRITICAL", "HIGH"}:
                recommendations.append("Do not enter credentials or sensitive information on this domain.")
                recommendations.append("Delay interactions until domain reputation is confirmed.")
                recommendations.append("Block domain in web proxy and email gateway filters.")
            elif risk == "MEDIUM":
                recommendations.append("Verify domain owner identity before proceeding.")
            else:
                recommendations.append("Domain reputation and infrastructure health checks passed baseline criteria.")

            return json.dumps({
                "success": True,
                "trust_score": trust_score,
                "risk": risk,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing DomainReputationTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "trust_score": 0,
                "risk": "CRITICAL",
                "dashboard": {"domain": domain, "age_days": 0, "registrar": "Unknown", "ssl_valid": False, "spf": False, "dkim": False, "dmarc": False, "trust_score": 0},
                "findings": [],
                "recommendations": [],
                "error": f"Domain reputation analysis failed: {str(e)}"
            }, indent=2)

    def _normalize_domain(self, raw_domain: str) -> str:
        """Strip protocols and paths to yield clean domain hostname."""
        d = raw_domain.strip().lower()
        if d.startswith(("http://", "https://")):
            d = d.split("://")[1]
        return d.split("/")[0].split(":")[0]

    def _get_whois_data(self, domain: str, warnings: List[str]) -> Dict[str, Any]:
        """Fetch WHOIS registration dates and compute age in days."""
        result = {"age_days": None, "registrar": "Unknown"}
        if not HAS_WHOIS:
            return result

        try:
            w = whois.whois(domain)
            if w:
                result["registrar"] = str(w.registrar or "Unknown")
                c_date = w.creation_date
                if isinstance(c_date, list):
                    c_date = c_date[0]

                if c_date and isinstance(c_date, datetime):
                    if c_date.tzinfo is None:
                        c_date = c_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    result["age_days"] = max(0, (now - c_date).days)
        except Exception as err:
            logger.debug(f"WHOIS lookup exception for {domain}: {err}")

        return result

    def _get_dns_health(self, domain: str, warnings: List[str]) -> Dict[str, bool]:
        """Query DNS records for MX, SPF, DKIM, and DMARC."""
        result = {"mx": False, "spf": False, "dkim": False, "dmarc": False}
        if not HAS_DNS:
            return result

        try:
            # MX Records
            try:
                mx_recs = dns.resolver.resolve(domain, 'MX')
                if len(mx_recs) > 0:
                    result["mx"] = True
            except Exception:
                pass

            # TXT Records (SPF)
            try:
                txt_recs = dns.resolver.resolve(domain, 'TXT')
                for rdata in txt_recs:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings]).lower()
                    if "v=spf1" in txt_str:
                        result["spf"] = True
                    if "v=dkim1" in txt_str or "dkim" in txt_str:
                        result["dkim"] = True
            except Exception:
                pass

            # DMARC Record
            try:
                dmarc_recs = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                for rdata in dmarc_recs:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings]).lower()
                    if "v=dmarc1" in txt_str:
                        result["dmarc"] = True
            except Exception:
                pass

        except Exception as err:
            logger.debug(f"DNS lookup exception for {domain}: {err}")

        return result

    def _get_ssl_info(self, domain: str, warnings: List[str]) -> Dict[str, Any]:
        """Establish SSL connection to inspect port 443 certificate."""
        result = {"valid": False, "reason": None}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        result["valid"] = True
        except ssl.SSLCertVerificationError as cert_err:
            result["reason"] = f"SSL Certificate Verification Error: {str(cert_err.verify_message if hasattr(cert_err, 'verify_message') else cert_err)}"
        except Exception as err:
            result["reason"] = f"Failed SSL connection on port 443 ({str(err)})"

        return result

    def _get_tld(self, domain: str) -> str:
        """Extract TLD string."""
        if HAS_TLDEXTRACT:
            return tldextract.extract(domain).suffix
        return domain.split(".")[-1]

    def _check_typosquatting(self, domain: str) -> Optional[str]:
        """Check for typosquatting / brand impersonation indicators."""
        brands = ["paypal", "microsoft", "apple", "google", "chase", "amazon", "netflix", "bankofamerica"]
        d_lower = domain.lower()

        for brand in brands:
            if brand in d_lower and not d_lower.startswith(f"{brand}."):
                parts = d_lower.split(".")
                if len(parts) >= 2 and brand != parts[-2]:
                    return brand
        return None
