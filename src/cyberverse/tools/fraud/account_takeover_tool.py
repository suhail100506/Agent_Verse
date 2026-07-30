import os
import json
import logging
from typing import Type, Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class AccountTakeoverToolInput(BaseModel):
    """Input schema for AccountTakeoverTool."""
    activity_data: Optional[Union[str, Dict[str, Any]]] = Field(
        None,
        description="Account activity payload dictionary or JSON string containing ATO indicators."
    )
    account_id: Optional[str] = Field(None, description="Account ID.")
    password_changed: Optional[bool] = Field(False, description="Whether password was recently changed.")
    mfa_disabled: Optional[bool] = Field(False, description="Whether MFA was disabled.")
    email_changed: Optional[bool] = Field(False, description="Whether recovery email was changed.")
    phone_changed: Optional[bool] = Field(False, description="Whether recovery phone was changed.")
    failed_logins: Optional[int] = Field(0, description="Count of recent failed login attempts.")
    credential_stuffing: Optional[bool] = Field(False, description="Whether credential stuffing pattern was detected.")
    impossible_travel: Optional[bool] = Field(False, description="Whether impossible travel was detected.")
    new_trusted_device: Optional[bool] = Field(False, description="Whether a new device was added as trusted.")


class AccountTakeoverTool(BaseTool):
    name: str = "Account Takeover Tool"
    description: str = (
        "Analyzes account modification logs, password changes, contact information updates, MFA status modifications, "
        "failed login bursts, credential stuffing signatures, and new trusted devices to compute a 0-100% Account Takeover (ATO) probability "
        "and risk rating (LOW, MEDIUM, HIGH, CRITICAL)."
    )
    args_schema: Type[BaseModel] = AccountTakeoverToolInput

    def _run(
        self,
        activity_data: Optional[Union[str, Dict[str, Any]]] = None,
        account_id: Optional[str] = None,
        password_changed: Optional[bool] = False,
        mfa_disabled: Optional[bool] = False,
        email_changed: Optional[bool] = False,
        phone_changed: Optional[bool] = False,
        failed_logins: Optional[int] = 0,
        credential_stuffing: Optional[bool] = False,
        impossible_travel: Optional[bool] = False,
        new_trusted_device: Optional[bool] = False
    ) -> str:
        """Execute account takeover (ATO) risk evaluation."""
        warnings: List[str] = []

        try:
            # 1. Resolve Input Payload
            data = self._resolve_activity_data(
                activity_data, account_id, password_changed, mfa_disabled, email_changed,
                phone_changed, failed_logins, credential_stuffing, impossible_travel, new_trusted_device
            )

            evidence: List[str] = []
            ato_score = 0

            # --- A. Authentication Mutation Indicators ---
            if data.get("mfa_disabled") is True:
                ato_score += 35
                evidence.append("MFA multi-factor authentication was recently disabled on account.")

            pw_changed = data.get("password_changed") is True
            email_changed = data.get("email_changed") is True
            phone_changed = data.get("phone_changed") is True

            if pw_changed and (email_changed or phone_changed):
                ato_score += 35
                evidence.append("High-risk ATO pattern: Password change combined with recovery email/phone modification.")
            elif pw_changed:
                ato_score += 15
                evidence.append("Account password was recently changed.")
            elif email_changed or phone_changed:
                ato_score += 20
                evidence.append("Account recovery email or phone number was recently modified.")

            # --- B. Attack & Failed Login Indicators ---
            if data.get("credential_stuffing") is True:
                ato_score += 30
                evidence.append("Credential stuffing attack signatures detected on account.")

            fl_count = int(data.get("failed_logins", 0) or 0)
            if fl_count >= 5:
                ato_score += 25
                evidence.append(f"Multiple failed login attempts ({fl_count} failures) prior to current session.")

            # --- C. Access & Device Anomalies ---
            if data.get("impossible_travel") is True:
                ato_score += 20
                evidence.append("Impossible travel velocity detected for account session.")

            if data.get("new_trusted_device") is True:
                ato_score += 15
                evidence.append("Unverified new device added as trusted device.")

            # 2. Finalize ATO Probability & Risk Level
            prob = max(0, min(100, ato_score))

            if prob >= 80:
                risk = "CRITICAL"
            elif prob >= 60:
                risk = "HIGH"
            elif prob >= 30:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            return json.dumps({
                "success": True,
                "takeover_probability": prob,
                "risk": risk,
                "evidence": list(dict.fromkeys(evidence)),
                "warnings": warnings,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing AccountTakeoverTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "takeover_probability": 0,
                "risk": "LOW",
                "evidence": [],
                "warnings": warnings,
                "error": f"Account takeover analysis failed: {str(e)}"
            }, indent=2)

    def _resolve_activity_data(
        self,
        activity_data: Optional[Union[str, Dict[str, Any]]],
        account_id: Optional[str],
        password_changed: Optional[bool],
        mfa_disabled: Optional[bool],
        email_changed: Optional[bool],
        phone_changed: Optional[bool],
        failed_logins: Optional[int],
        credential_stuffing: Optional[bool],
        impossible_travel: Optional[bool],
        new_trusted_device: Optional[bool]
    ) -> Dict[str, Any]:
        """Resolve account activity payload dictionary."""
        data: Dict[str, Any] = {}

        if activity_data:
            if isinstance(activity_data, str):
                try:
                    data = json.loads(activity_data)
                except Exception:
                    pass
            elif isinstance(activity_data, dict):
                data = activity_data

        if account_id:
            data["account_id"] = account_id
        if password_changed is not None:
            data["password_changed"] = password_changed
        if mfa_disabled is not None:
            data["mfa_disabled"] = mfa_disabled
        if email_changed is not None:
            data["email_changed"] = email_changed
        if phone_changed is not None:
            data["phone_changed"] = phone_changed
        if failed_logins is not None:
            data["failed_logins"] = failed_logins
        if credential_stuffing is not None:
            data["credential_stuffing"] = credential_stuffing
        if impossible_travel is not None:
            data["impossible_travel"] = impossible_travel
        if new_trusted_device is not None:
            data["new_trusted_device"] = new_trusted_device

        return data
