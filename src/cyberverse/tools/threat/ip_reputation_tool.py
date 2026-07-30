import os
import json
import logging
import ipaddress
from typing import Type, Dict, Any, List, Optional
import requests
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class IPReputationToolInput(BaseModel):
    """Input schema for IPReputationTool."""
    ip_address: str = Field(..., description="IPv4 or IPv6 string address to query for threat reputation.")


class IPReputationTool(BaseTool):
    name: str = "IP Reputation Tool"
    description: str = (
        "Validates IPv4 and IPv6 addresses, checks for public/private network allocation, and queries AbuseIPDB threat intelligence APIs "
        "to extract abuse confidence scores, total abuse report counts, ISP details, domain info, usage types, and risk ratings."
    )
    args_schema: Type[BaseModel] = IPReputationToolInput

    def _run(self, ip_address: str) -> str:
        """Execute IP address validation and threat reputation lookup."""
        warnings: List[str] = []

        if not ip_address or not isinstance(ip_address, str):
            return json.dumps({
                "success": False,
                "ip": str(ip_address),
                "is_public": False,
                "country": "Unknown",
                "isp": "Unknown",
                "domain": "Unknown",
                "usage_type": "Unknown",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": "ip_address argument must be a valid non-empty string."
            }, indent=2)

        clean_ip = ip_address.strip().strip('"').strip("'")

        # 1. Validate & Parse IP Address (IPv4 / IPv6)
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return json.dumps({
                "success": False,
                "ip": clean_ip,
                "is_public": False,
                "country": "Unknown",
                "isp": "Unknown",
                "domain": "Unknown",
                "usage_type": "Unknown",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": f"Invalid IPv4/IPv6 address syntax: '{clean_ip}'"
            }, indent=2)

        # 2. Check for Non-Public / Internal IP Allocations
        is_public = not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_multicast or
            ip_obj.is_reserved or
            ip_obj.is_link_local
        )

        if not is_public:
            warnings.append(f"Private/Internal IP address ({clean_ip}) provided; online threat lookup skipped.")
            return json.dumps({
                "success": True,
                "ip": clean_ip,
                "is_public": False,
                "country": "Internal / Private",
                "isp": "Private Network",
                "domain": "local",
                "usage_type": "Private Network / Loopback",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": None
            }, indent=2)

        # 3. Check for AbuseIPDB API Key
        api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        if not api_key:
            warnings.append("ABUSEIPDB_API_KEY environment variable is not set. AbuseIPDB threat lookup skipped.")
            return json.dumps({
                "success": True,
                "ip": clean_ip,
                "is_public": True,
                "country": "Unknown",
                "isp": "Unknown",
                "domain": "Unknown",
                "usage_type": "Public IP",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": None
            }, indent=2)

        # 4. Query AbuseIPDB v2 REST API
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": clean_ip,
            "maxAgeInDays": 90,
            "verbose": "true"
        }
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)

            # Handle HTTP status code cases
            if response.status_code in {401, 403}:
                warnings.append("AbuseIPDB API Key is invalid or unauthorized.")
                return json.dumps({
                    "success": True,
                    "ip": clean_ip,
                    "is_public": True,
                    "country": "Unknown",
                    "isp": "Unknown",
                    "domain": "Unknown",
                    "usage_type": "Public IP",
                    "abuse_score": 0,
                    "reports": 0,
                    "risk": "LOW",
                    "warnings": warnings,
                    "error": None
                }, indent=2)

            elif response.status_code == 429:
                warnings.append("AbuseIPDB API rate limit exceeded (HTTP 429 Request Limit).")
                return json.dumps({
                    "success": True,
                    "ip": clean_ip,
                    "is_public": True,
                    "country": "Unknown",
                    "isp": "Unknown",
                    "domain": "Unknown",
                    "usage_type": "Public IP",
                    "abuse_score": 0,
                    "reports": 0,
                    "risk": "LOW",
                    "warnings": warnings,
                    "error": None
                }, indent=2)

            elif response.status_code != 200:
                warnings.append(f"AbuseIPDB API returned unexpected HTTP status code {response.status_code}.")
                return json.dumps({
                    "success": False,
                    "ip": clean_ip,
                    "is_public": True,
                    "country": "Unknown",
                    "isp": "Unknown",
                    "domain": "Unknown",
                    "usage_type": "Public IP",
                    "abuse_score": 0,
                    "reports": 0,
                    "risk": "LOW",
                    "warnings": warnings,
                    "error": f"AbuseIPDB API HTTP {response.status_code}"
                }, indent=2)

            # 5. Parse API Payload
            json_data = response.json()
            data = json_data.get("data", {})

            abuse_score = int(data.get("abuseConfidenceScore", 0))
            country = data.get("countryName") or data.get("countryCode") or "Unknown"
            isp = data.get("isp") or "Unknown"
            domain = data.get("domain") or "Unknown"
            usage_type = data.get("usageType") or "Public IP"
            total_reports = int(data.get("totalReports", 0))

            # 6. Risk Rating Engine
            if abuse_score >= 80:
                risk = "CRITICAL"
            elif abuse_score >= 50:
                risk = "HIGH"
            elif abuse_score >= 15:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            return json.dumps({
                "success": True,
                "ip": clean_ip,
                "is_public": True,
                "country": country,
                "isp": isp,
                "domain": domain,
                "usage_type": usage_type,
                "abuse_score": abuse_score,
                "reports": total_reports,
                "risk": risk,
                "warnings": warnings,
                "error": None
            }, indent=2)

        except requests.Timeout:
            logger.warning("AbuseIPDB API request timed out.")
            return json.dumps({
                "success": False,
                "ip": clean_ip,
                "is_public": True,
                "country": "Unknown",
                "isp": "Unknown",
                "domain": "Unknown",
                "usage_type": "Public IP",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": "Network request to AbuseIPDB API timed out (10s limit)."
            }, indent=2)
        except Exception as e:
            logger.error(f"Error executing IPReputationTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "ip": clean_ip,
                "is_public": True,
                "country": "Unknown",
                "isp": "Unknown",
                "domain": "Unknown",
                "usage_type": "Public IP",
                "abuse_score": 0,
                "reports": 0,
                "risk": "LOW",
                "warnings": warnings,
                "error": f"IP reputation query failed: {str(e)}"
            }, indent=2)
