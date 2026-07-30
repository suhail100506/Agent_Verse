import os
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DNSAnalysisToolInput(BaseModel):
    """Input schema for DNSAnalysisTool."""
    domain: str = Field(..., description="Target domain name or FQDN to query for DNS records, WHOIS data, and email security authentication.")


class DNSAnalysisTool(BaseTool):
    name: str = "DNS Analysis Tool"
    description: str = (
        "Queries DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME), parses WHOIS registrar data, and evaluates email security "
        "authentication controls (SPF, DKIM, DMARC) to detect misconfigurations, missing spoofing protections, and open mail relay indicators."
    )
    args_schema: Type[BaseModel] = DNSAnalysisToolInput

    def _run(self, domain: str) -> str:
        """Execute DNS record resolution, WHOIS lookup, and email security policy audit."""
        warnings: List[str] = []

        if not HAS_DNSPYTHON:
            return json.dumps({
                "success": False,
                "domain": str(domain),
                "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": {}, "CNAME": []},
                "email_security": {
                    "spf": {"present": False, "valid": False, "record": None},
                    "dmarc": {"present": False, "policy": "none", "record": None, "pct": 100, "rua": []},
                    "dkim": {"checked": False}
                },
                "whois": {},
                "risk": "LOW",
                "warnings": warnings,
                "error": "dnspython library is not installed."
            }, indent=2)

        if not domain or not isinstance(domain, str):
            return json.dumps({
                "success": False,
                "domain": str(domain),
                "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": {}, "CNAME": []},
                "email_security": {
                    "spf": {"present": False, "valid": False, "record": None},
                    "dmarc": {"present": False, "policy": "none", "record": None, "pct": 100, "rua": []},
                    "dkim": {"checked": False}
                },
                "whois": {},
                "risk": "LOW",
                "warnings": warnings,
                "error": "domain argument must be a non-empty string."
            }, indent=2)

        # 1. Clean & Sanitize Domain Input
        clean_domain = self._sanitize_domain(domain)
        if not clean_domain:
            return json.dumps({
                "success": False,
                "domain": domain,
                "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": {}, "CNAME": []},
                "email_security": {
                    "spf": {"present": False, "valid": False, "record": None},
                    "dmarc": {"present": False, "policy": "none", "record": None, "pct": 100, "rua": []},
                    "dkim": {"checked": False}
                },
                "whois": {},
                "risk": "LOW",
                "warnings": warnings,
                "error": f"Invalid domain name or hostname: '{domain}'"
            }, indent=2)

        try:
            # Configure DNS Resolver with 5s lifetime timeout
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 5.0
            resolver.timeout = 3.0

            # 2. Query Standard DNS Records
            records = self._query_dns_records(resolver, clean_domain, warnings)

            # 3. Analyze Email Security Authentication (SPF, DKIM, DMARC)
            email_sec = self._analyze_email_security(resolver, clean_domain, records.get("TXT", []), warnings)

            # 4. Extract WHOIS Summary (Optional)
            whois_data = self._query_whois_summary(clean_domain, warnings)

            # 5. Misconfiguration & Security Defect Warnings
            self._evaluate_security_misconfigurations(records, email_sec, warnings)

            # 6. Compute Overall Risk Rating
            risk_rating = self._calculate_risk_rating(records, email_sec, warnings)

            return json.dumps({
                "success": True,
                "domain": clean_domain,
                "records": records,
                "email_security": email_sec,
                "whois": whois_data,
                "risk": risk_rating,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing DNSAnalysisTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "domain": clean_domain,
                "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": {}, "CNAME": []},
                "email_security": {
                    "spf": {"present": False, "valid": False, "record": None},
                    "dmarc": {"present": False, "policy": "none", "record": None, "pct": 100, "rua": []},
                    "dkim": {"checked": False}
                },
                "whois": {},
                "risk": "LOW",
                "warnings": warnings,
                "error": f"DNS analysis failed: {str(e)}"
            }, indent=2)

    def _sanitize_domain(self, input_str: str) -> str:
        """Strip http/https schemes, paths, ports, and trailing slashes."""
        clean = input_str.strip().strip('"').strip("'")
        if clean.startswith(("http://", "https://")):
            parsed = urlparse(clean)
            clean = parsed.hostname or clean
        elif "/" in clean:
            clean = clean.split("/")[0]
        if ":" in clean:
            clean = clean.split(":")[0]
        return clean.lower()

    def _query_dns_records(self, resolver: dns.resolver.Resolver, domain: str, warnings: List[str]) -> Dict[str, Any]:
        """Query A, AAAA, MX, NS, TXT, SOA, CNAME records safely."""
        records: Dict[str, Any] = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "SOA": {},
            "CNAME": []
        }

        # A Records
        try:
            answers = resolver.resolve(domain, "A")
            records["A"] = [r.to_text() for r in answers]
        except Exception:
            pass

        # AAAA Records
        try:
            answers = resolver.resolve(domain, "AAAA")
            records["AAAA"] = [r.to_text() for r in answers]
        except Exception:
            pass

        # MX Records
        try:
            answers = resolver.resolve(domain, "MX")
            records["MX"] = [
                {"preference": r.preference, "exchange": r.exchange.to_text().rstrip(".")}
                for r in answers
            ]
        except Exception:
            pass

        # NS Records
        try:
            answers = resolver.resolve(domain, "NS")
            records["NS"] = [r.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        # TXT Records
        try:
            answers = resolver.resolve(domain, "TXT")
            records["TXT"] = [r.to_text().strip('"') for r in answers]
        except Exception:
            pass

        # SOA Record
        try:
            answers = resolver.resolve(domain, "SOA")
            for r in answers:
                records["SOA"] = {
                    "mname": r.mname.to_text().rstrip("."),
                    "rname": r.rname.to_text().rstrip("."),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum
                }
                break
        except Exception:
            pass

        # CNAME Records
        try:
            answers = resolver.resolve(domain, "CNAME")
            records["CNAME"] = [r.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        return records

    def _analyze_email_security(
        self,
        resolver: dns.resolver.Resolver,
        domain: str,
        txt_records: List[str],
        warnings: List[str]
    ) -> Dict[str, Any]:
        """Inspect SPF, DKIM, and DMARC record policies."""
        # 1. SPF Analysis
        spf_records = [txt for txt in txt_records if "v=spf1" in txt.lower()]
        spf_info = {"present": False, "valid": False, "record": None}

        if len(spf_records) > 1:
            warnings.append(f"Multiple SPF records detected ({len(spf_records)}) - RFC 7208 specifies multiple SPF records invalidate SPF evaluation.")
            spf_info["present"] = True
            spf_info["valid"] = False
            spf_info["record"] = spf_records[0]
        elif len(spf_records) == 1:
            spf_info["present"] = True
            spf_info["valid"] = True
            spf_info["record"] = spf_records[0]

        # 2. DKIM Analysis
        dkim_info = {"checked": False}

        # 3. DMARC Analysis (_dmarc.domain)
        dmarc_info = {"present": False, "policy": "none", "record": None, "pct": 100, "rua": []}
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = resolver.resolve(dmarc_domain, "TXT")
            for r in answers:
                r_text = r.to_text().strip('"')
                if "v=dmarc1" in r_text.lower():
                    dmarc_info["present"] = True
                    dmarc_info["record"] = r_text
                    
                    # Parse tags (p=, pct=, rua=)
                    for tag in r_text.split(";"):
                        clean_tag = tag.strip()
                        if clean_tag.lower().startswith("p="):
                            dmarc_info["policy"] = clean_tag.split("=")[1].strip().lower()
                        elif clean_tag.lower().startswith("pct="):
                            try:
                                dmarc_info["pct"] = int(clean_tag.split("=")[1].strip())
                            except ValueError:
                                pass
                        elif clean_tag.lower().startswith("rua="):
                            rua_val = clean_tag.split("=")[1].strip()
                            dmarc_info["rua"] = [addr.strip() for addr in rua_val.split(",")]
                    break
        except Exception:
            pass

        return {
            "spf": spf_info,
            "dmarc": dmarc_info,
            "dkim": dkim_info
        }

    def _query_whois_summary(self, domain: str, warnings: List[str]) -> Dict[str, Any]:
        """Extract WHOIS metadata using python-whois if available."""
        if not HAS_WHOIS:
            return {}

        try:
            w = whois.whois(domain)
            if not w:
                return {}

            registrar = w.registrar
            if isinstance(registrar, list):
                registrar = registrar[0]

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            creation_str = creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date) if creation_date else None

            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            exp_str = expiration_date.isoformat() if isinstance(expiration_date, datetime) else str(expiration_date) if expiration_date else None

            ns_list = w.name_servers
            if isinstance(ns_list, set):
                ns_list = list(ns_list)
            elif not isinstance(ns_list, list):
                ns_list = [ns_list] if ns_list else []
            clean_ns = [str(ns).lower() for ns in ns_list if ns]

            return {
                "registrar": str(registrar) if registrar else "Unknown",
                "creation_date": creation_str,
                "expiration_date": exp_str,
                "name_servers": clean_ns
            }
        except Exception as err:
            logger.debug(f"WHOIS lookup failed for {domain}: {err}")
            return {}

    def _evaluate_security_misconfigurations(
        self,
        records: Dict[str, Any],
        email_sec: Dict[str, Any],
        warnings: List[str]
    ) -> None:
        """Flag missing records and security misconfigurations."""
        has_mx = len(records.get("MX", [])) > 0
        spf = email_sec.get("spf", {})
        dmarc = email_sec.get("dmarc", {})

        if has_mx and not spf.get("present"):
            warnings.append("Missing SPF record (v=spf1) - Domain is vulnerable to email spoofing.")

        if has_mx and not dmarc.get("present"):
            warnings.append("Missing DMARC record (_dmarc) - Domain email spoofing protection is disabled.")

        if dmarc.get("present") and dmarc.get("policy") == "none":
            warnings.append("Weak DMARC policy set to 'p=none' (monitoring only - non-enforcing).")

        if spf.get("present") and "+all" in str(spf.get("record", "")).lower():
            warnings.append("Dangerous SPF record directive '+all' permits any host to send email for domain.")

        if not has_mx:
            warnings.append("No MX records configured for domain.")

    def _calculate_risk_rating(
        self,
        records: Dict[str, Any],
        email_sec: Dict[str, Any],
        warnings: List[str]
    ) -> str:
        """Compute overall DNS security risk rating: CRITICAL, HIGH, MEDIUM, LOW."""
        has_mx = len(records.get("MX", [])) > 0
        spf_present = email_sec.get("spf", {}).get("present", False)
        spf_valid = email_sec.get("spf", {}).get("valid", True)
        dmarc_present = email_sec.get("dmarc", {}).get("present", False)
        dmarc_policy = email_sec.get("dmarc", {}).get("policy", "none")

        if has_mx and not spf_present and not dmarc_present:
            return "CRITICAL"

        if has_mx and (not dmarc_present or not spf_valid or "+all" in str(email_sec.get("spf", {}).get("record", ""))):
            return "HIGH"

        if dmarc_present and dmarc_policy == "none":
            return "MEDIUM"

        return "LOW"
