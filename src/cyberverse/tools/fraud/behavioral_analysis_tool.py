import os
import json
import logging
from datetime import datetime
from typing import Type, Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class BehavioralAnalysisToolInput(BaseModel):
    """Input schema for BehavioralAnalysisTool."""
    user_activity_data: Optional[Union[str, Dict[str, Any]]] = Field(
        None,
        description="Historical user activity payload dictionary or JSON string containing login, session, device, and location histories."
    )
    user_id: Optional[str] = Field(None, description="Target user account ID.")
    login_history: Optional[List[Dict[str, Any]]] = Field(None, description="List of historical login events.")
    session_history: Optional[List[Dict[str, Any]]] = Field(None, description="List of historical session events.")
    device_history: Optional[List[Dict[str, Any]]] = Field(None, description="List of historical device usage records.")
    location_history: Optional[List[Dict[str, Any]]] = Field(None, description="List of historical location records.")


class BehavioralAnalysisTool(BaseTool):
    name: str = "Behavioral Analysis Tool"
    description: str = (
        "Analyzes historical user behavior (login failures, credential stuffing indicators, session duration anomalies, "
        "new device usage, new location logins, and impossible travel patterns) to compute a 0-100 behavior score, "
        "risk rating (LOW, MEDIUM, HIGH, CRITICAL), telemetry dashboard, evidence list, and recommendations."
    )
    args_schema: Type[BaseModel] = BehavioralAnalysisToolInput

    def _run(
        self,
        user_activity_data: Optional[Union[str, Dict[str, Any]]] = None,
        user_id: Optional[str] = None,
        login_history: Optional[List[Dict[str, Any]]] = None,
        session_history: Optional[List[Dict[str, Any]]] = None,
        device_history: Optional[List[Dict[str, Any]]] = None,
        location_history: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """Execute historical user behavior anomaly analysis."""
        warnings: List[str] = []

        try:
            # 1. Parse Input Payload
            data = self._resolve_activity_data(
                user_activity_data, user_id, login_history, session_history, device_history, location_history
            )

            logins = data.get("login_history", [])
            sessions = data.get("session_history", [])
            devices = data.get("device_history", [])
            locations = data.get("location_history", [])

            evidence: List[str] = []
            recommendations: List[str] = []
            behavior_score = 0
            active_factors = 0

            # --- A. Login Pattern & Failure Analysis ---
            failed_logins = sum(1 for log in logins if log.get("status") in {"failed", "FAILURE", False})
            if failed_logins >= 8:
                behavior_score += 40
                evidence.append(f"Brute-force / credential stuffing pattern: {failed_logins} failed login attempts detected.")
            elif failed_logins >= 3:
                behavior_score += 20
                evidence.append(f"Multiple failed login attempts ({failed_logins} failures) detected.")

            if logins:
                active_factors += 1

            # --- B. Device Anomaly Analysis ---
            new_devices_count = 0
            known_device_ids = set()
            for dev in devices[:-1]:  # Prior history
                if dev.get("device_id"):
                    known_device_ids.add(dev.get("device_id"))

            recent_device = devices[-1].get("device_id") if devices else None
            if recent_device and known_device_ids and recent_device not in known_device_ids:
                new_devices_count += 1
                behavior_score += 20
                evidence.append(f"First-time / new device detected ('{recent_device}').")

            if devices:
                active_factors += 1

            # --- C. Location & Impossible Travel Analysis ---
            new_locations_count = 0
            impossible_travel = False

            known_countries = {loc.get("country") for loc in locations[:-1] if loc.get("country")}
            recent_country = locations[-1].get("country") if locations else None

            if recent_country and known_countries and recent_country not in known_countries:
                new_locations_count += 1
                behavior_score += 25
                evidence.append(f"Login from new country detected ('{recent_country}').")

            # Impossible Travel Check (Sequential location jump < 2 hours across countries)
            if len(locations) >= 2:
                last_loc = locations[-1]
                prev_loc = locations[-2]

                c1, c2 = prev_loc.get("country"), last_loc.get("country")
                t1_str, t2_str = prev_loc.get("timestamp"), last_loc.get("timestamp")

                if c1 and c2 and c1 != c2 and t1_str and t2_str:
                    try:
                        dt1 = datetime.fromisoformat(t1_str.replace("Z", "+00:00"))
                        dt2 = datetime.fromisoformat(t2_str.replace("Z", "+00:00"))
                        hours_diff = abs((dt2 - dt1).total_seconds()) / 3600.0

                        if hours_diff < 3.0:
                            impossible_travel = True
                            behavior_score += 35
                            evidence.append(f"Impossible travel identified: Location changed from '{c1}' to '{c2}' within {hours_diff:.1f} hours.")
                    except Exception:
                        pass

            if locations:
                active_factors += 1

            # --- D. Off-Hours & Session Anomalies ---
            for log in logins:
                ts = log.get("timestamp")
                if ts:
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if 2 <= dt.hour <= 5:
                            behavior_score += 10
                            evidence.append(f"Login outside normal working hours ({dt.strftime('%H:%M')} UTC).")
                            break
                    except Exception:
                        pass

            # 2. Finalize Behavior Score & Risk Rating
            final_behavior_score = min(100, behavior_score)

            if final_behavior_score >= 80:
                risk = "CRITICAL"
            elif final_behavior_score >= 60:
                risk = "HIGH"
            elif final_behavior_score >= 30:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            confidence = min(99, 75 + (active_factors * 6)) if active_factors > 0 else 50

            # 3. Formulate Telemetry Dashboard
            dashboard = {
                "failed_logins": failed_logins,
                "new_devices": new_devices_count,
                "new_locations": new_locations_count,
                "impossible_travel": impossible_travel,
                "behavior_score": final_behavior_score
            }

            # 4. Formulate Recommendations
            if risk in {"CRITICAL", "HIGH"}:
                recommendations.append("Require multi-factor authentication (MFA) immediately.")
                recommendations.append("Challenge user with step-up authentication.")
                recommendations.append("Temporarily restrict high-value transactions.")
                recommendations.append("Monitor account activity closely.")
            elif risk == "MEDIUM":
                recommendations.append("Prompt user for secondary email/SMS verification.")
                recommendations.append("Log behavioral anomaly for security operations review.")
            else:
                recommendations.append("User behavior aligns with historical baseline.")

            return json.dumps({
                "success": True,
                "behavior_score": final_behavior_score,
                "risk": risk,
                "confidence": confidence,
                "dashboard": dashboard,
                "evidence": list(dict.fromkeys(evidence)),
                "recommendations": list(dict.fromkeys(recommendations)),
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing BehavioralAnalysisTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "behavior_score": 0,
                "risk": "LOW",
                "confidence": 0,
                "dashboard": {"failed_logins": 0, "new_devices": 0, "new_locations": 0, "impossible_travel": False, "behavior_score": 0},
                "evidence": [],
                "recommendations": [],
                "error": f"Behavioral analysis failed: {str(e)}"
            }, indent=2)

    def _resolve_activity_data(
        self,
        user_activity_data: Optional[Union[str, Dict[str, Any]]],
        user_id: Optional[str],
        login_history: Optional[List[Dict[str, Any]]],
        session_history: Optional[List[Dict[str, Any]]],
        device_history: Optional[List[Dict[str, Any]]],
        location_history: Optional[List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Resolve user activity payload dictionary."""
        data: Dict[str, Any] = {}

        if user_activity_data:
            if isinstance(user_activity_data, str):
                try:
                    data = json.loads(user_activity_data)
                except Exception:
                    pass
            elif isinstance(user_activity_data, dict):
                data = user_activity_data

        if user_id:
            data["user_id"] = user_id
        if login_history is not None:
            data["login_history"] = login_history
        if session_history is not None:
            data["session_history"] = session_history
        if device_history is not None:
            data["device_history"] = device_history
        if location_history is not None:
            data["location_history"] = location_history

        return data
