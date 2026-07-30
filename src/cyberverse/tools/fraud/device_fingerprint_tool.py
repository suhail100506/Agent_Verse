import os
import re
import json
import hashlib
import ipaddress
import logging
from typing import Type, Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

try:
    import user_agents
    HAS_USER_AGENTS = True
except ImportError:
    HAS_USER_AGENTS = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class DeviceFingerprintToolInput(BaseModel):
    """Input schema for DeviceFingerprintTool."""
    device_data: Optional[Union[str, Dict[str, Any]]] = Field(
        None,
        description="Client device metadata payload dictionary or JSON string."
    )
    device_id: Optional[str] = Field(None, description="Device identifier string.")
    user_id: Optional[str] = Field(None, description="User account ID.")
    browser: Optional[str] = Field(None, description="Browser name (e.g. Chrome, Firefox, Safari, Tor Browser).")
    browser_version: Optional[str] = Field(None, description="Browser version string.")
    operating_system: Optional[str] = Field(None, description="OS name (e.g. Windows, macOS, Linux, Android, iOS).")
    os_version: Optional[str] = Field(None, description="OS version string.")
    screen_resolution: Optional[str] = Field(None, description="Screen resolution (e.g. 1920x1080).")
    timezone: Optional[str] = Field(None, description="Timezone (e.g. UTC, America/New_York).")
    language: Optional[str] = Field(None, description="Preferred language (e.g. en-US).")
    ip_address: Optional[str] = Field(None, description="Client IP address.")
    user_agent: Optional[str] = Field(None, description="HTTP User-Agent string.")
    cookies_enabled: Optional[bool] = Field(True, description="Whether cookies are enabled.")
    javascript_enabled: Optional[bool] = Field(True, description="Whether JavaScript is enabled.")
    touch_support: Optional[bool] = Field(False, description="Whether touch input is supported.")
    webdriver: Optional[bool] = Field(False, description="Whether navigator.webdriver automation flag is active.")


class DeviceFingerprintTool(BaseTool):
    name: str = "Device Fingerprint Tool"
    description: str = (
        "Analyzes client device metadata, User-Agent headers, browser environment features, automation frameworks "
        "(Selenium, Puppeteer, Playwright), headless browsers, virtual machines, and VPN/Tor exit nodes to generate "
        "a SHA256 device fingerprint and calculate a 0-100 Device Trust Score."
    )
    args_schema: Type[BaseModel] = DeviceFingerprintToolInput

    def _run(
        self,
        device_data: Optional[Union[str, Dict[str, Any]]] = None,
        device_id: Optional[str] = None,
        user_id: Optional[str] = None,
        browser: Optional[str] = None,
        browser_version: Optional[str] = None,
        operating_system: Optional[str] = None,
        os_version: Optional[str] = None,
        screen_resolution: Optional[str] = None,
        timezone: Optional[str] = None,
        language: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        cookies_enabled: Optional[bool] = True,
        javascript_enabled: Optional[bool] = True,
        touch_support: Optional[bool] = False,
        webdriver: Optional[bool] = False
    ) -> str:
        """Execute client device fingerprinting and trust verification."""
        warnings: List[str] = []

        try:
            # 1. Parse Input Payload
            data = self._resolve_device_data(
                device_data, device_id, user_id, browser, browser_version, operating_system,
                os_version, screen_resolution, timezone, language, ip_address, user_agent,
                cookies_enabled, javascript_enabled, touch_support, webdriver
            )

            # 2. Compute Deterministic SHA256 Fingerprint Hash
            fingerprint_hash = self._generate_sha256_fingerprint(data)

            findings: List[str] = []
            recommendations: List[str] = []
            trust_score = 100

            # --- A. Browser & User-Agent Analysis ---
            ua_str = str(data.get("user_agent", "")).strip()
            browser_name = str(data.get("browser", "")).strip() or "Unknown"

            if HAS_USER_AGENTS and ua_str:
                try:
                    parsed_ua = user_agents.parse(ua_str)
                    if not browser_name or browser_name == "Unknown":
                        browser_name = parsed_ua.browser.family
                    if not data.get("operating_system"):
                        data["operating_system"] = parsed_ua.os.family
                except Exception:
                    pass

            if not ua_str:
                trust_score -= 20
                findings.append("Missing HTTP User-Agent string.")

            if "tor" in browser_name.lower() or "tor" in ua_str.lower():
                trust_score -= 25
                findings.append("Tor Browser usage detected.")

            # --- B. Automation & Headless Browser Detection ---
            is_headless = False
            if "headless" in ua_str.lower() or "phantomjs" in ua_str.lower() or "selenium" in ua_str.lower():
                is_headless = True
                trust_score -= 35
                findings.append("Headless browser or web automation framework (Selenium/Puppeteer) detected.")

            if data.get("webdriver") is True or "playwright" in ua_str.lower():
                trust_score -= 30
                findings.append("Webdriver automation indicators present (navigator.webdriver = true).")

            # --- C. Virtual Machine & Emulator Detection ---
            is_vm = False
            is_emulator = False
            os_name = str(data.get("operating_system", "")).strip() or "Unknown"

            if any(v in os_name.lower() or v in ua_str.lower() for v in ["vmware", "virtualbox", "qemu", "xen"]):
                is_vm = True
                trust_score -= 20
                findings.append("Virtual machine environment detected.")

            if any(e in os_name.lower() or e in ua_str.lower() for e in ["bluestacks", "nox", "genymotion", "sdk_gphone"]):
                is_emulator = True
                trust_score -= 20
                findings.append("Android/iOS emulator environment detected.")

            # --- D. Network & IP Analysis ---
            is_vpn = False
            is_tor = "tor" in browser_name.lower() or "tor" in ua_str.lower()
            ip_str = str(data.get("ip_address", "")).strip()

            if ip_str:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback:
                        findings.append(f"Internal / private IP address used ({ip_str}).")
                except ValueError:
                    pass

            if data.get("vpn") is True or "vpn" in ip_str.lower():
                is_vpn = True
                trust_score -= 20
                findings.append("VPN connection detected.")

            # --- E. Browser Capabilities (Cookies / JavaScript) ---
            if data.get("cookies_enabled") is False:
                trust_score -= 10
                findings.append("Browser cookies disabled.")
            if data.get("javascript_enabled") is False:
                trust_score -= 15
                findings.append("JavaScript execution disabled.")

            # 3. Finalize Device Trust Score & Risk Categorization
            final_trust_score = max(0, min(100, trust_score))

            if final_trust_score < 40:
                risk = "CRITICAL"
            elif final_trust_score < 60:
                risk = "HIGH"
            elif final_trust_score < 80:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            # 4. Formulate Telemetry Dashboard
            dashboard = {
                "browser": browser_name,
                "os": f"{os_name} {data.get('os_version', '')}".strip(),
                "fingerprint": fingerprint_hash[:16] + "...",
                "vpn": is_vpn,
                "tor": is_tor,
                "headless": is_headless,
                "emulator": is_emulator,
                "vm": is_vm
            }

            # 5. Formulate Recommendations
            if risk in {"CRITICAL", "HIGH"}:
                recommendations.append("Block automated login and flag device.")
                recommendations.append("Require multi-factor authentication (MFA).")
                recommendations.append("Verify device ownership with step-up challenge.")
            elif risk == "MEDIUM":
                recommendations.append("Require step-up device verification.")
                recommendations.append("Log suspicious device fingerprint for security review.")
            else:
                recommendations.append("Device fingerprint is trusted.")

            return json.dumps({
                "success": True,
                "device_trust_score": final_trust_score,
                "risk": risk,
                "fingerprint": fingerprint_hash,
                "dashboard": dashboard,
                "findings": list(dict.fromkeys(findings)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error("Error executing DeviceFingerprintTool (metadata suppressed).", exc_info=True)
            return json.dumps({
                "success": False,
                "device_trust_score": 0,
                "risk": "CRITICAL",
                "fingerprint": "",
                "dashboard": {"browser": "Unknown", "os": "Unknown", "fingerprint": "", "vpn": False, "tor": False, "headless": False, "emulator": False, "vm": False},
                "findings": [],
                "recommendations": [],
                "error": f"Device fingerprint analysis failed: {str(e)}"
            }, indent=2)

    def _generate_sha256_fingerprint(self, data: Dict[str, Any]) -> str:
        """Compute deterministic SHA256 fingerprint hash from normalized device attributes."""
        normalized_str = (
            f"{data.get('browser', '')}|"
            f"{data.get('browser_version', '')}|"
            f"{data.get('operating_system', '')}|"
            f"{data.get('os_version', '')}|"
            f"{data.get('screen_resolution', '')}|"
            f"{data.get('timezone', '')}|"
            f"{data.get('language', '')}|"
            f"{data.get('user_agent', '')}"
        )
        return hashlib.sha256(normalized_str.encode("utf-8")).hexdigest()

    def _resolve_device_data(
        self,
        device_data: Optional[Union[str, Dict[str, Any]]],
        device_id: Optional[str],
        user_id: Optional[str],
        browser: Optional[str],
        browser_version: Optional[str],
        operating_system: Optional[str],
        os_version: Optional[str],
        screen_resolution: Optional[str],
        timezone: Optional[str],
        language: Optional[str],
        ip_address: Optional[str],
        user_agent: Optional[str],
        cookies_enabled: Optional[bool],
        javascript_enabled: Optional[bool],
        touch_support: Optional[bool],
        webdriver: Optional[bool] = False
    ) -> Dict[str, Any]:
        """Resolve client device metadata payload dictionary."""
        data: Dict[str, Any] = {}

        if device_data:
            if isinstance(device_data, str):
                try:
                    data = json.loads(device_data)
                except Exception:
                    pass
            elif isinstance(device_data, dict):
                data = device_data

        if device_id:
            data["device_id"] = device_id
        if user_id:
            data["user_id"] = user_id
        if browser:
            data["browser"] = browser
        if browser_version:
            data["browser_version"] = browser_version
        if operating_system:
            data["operating_system"] = operating_system
        if os_version:
            data["os_version"] = os_version
        if screen_resolution:
            data["screen_resolution"] = screen_resolution
        if timezone:
            data["timezone"] = timezone
        if language:
            data["language"] = language
        if ip_address:
            data["ip_address"] = ip_address
        if user_agent:
            data["user_agent"] = user_agent
        if cookies_enabled is not None:
            data["cookies_enabled"] = cookies_enabled
        if javascript_enabled is not None:
            data["javascript_enabled"] = javascript_enabled
        if touch_support is not None:
            data["touch_support"] = touch_support
        if webdriver is not None:
            data["webdriver"] = webdriver

        return data
