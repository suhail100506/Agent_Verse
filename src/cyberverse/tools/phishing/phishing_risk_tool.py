"""
PhishingRiskTool — Unified Enterprise Phishing Risk Assessment
==============================================================
Aggregates the outputs of all four Phishing Detection Specialist tools:

    1. EmailHeaderAnalysisTool  → header_score  (0–100)
    2. URLInspectionTool        → url_score     (0–100)
    3. DomainReputationTool     → domain_score  derived from trust_score (0–100, inverted)
    4. ContentAnalysisTool      → content_score (0–100)

into a single, enterprise-grade phishing risk assessment.

Aggregation Architecture
------------------------
Weighted score fusion (weights calibrated for enterprise phishing workflows):

    header_score  × 0.25   (authentication failures are highly authoritative)
    url_score     × 0.30   (URL is the primary attack vector in phishing)
    domain_score  × 0.20   (domain intelligence is a supporting signal)
    content_score × 0.25   (content analysis closes the loop)

Confidence Engine
-----------------
Starts at 50%, then:
    + 10% per tool that returned a valid result    (max +40%)
    +  8% per tool whose risk ≥ HIGH               (max +32%)
    +  5% bonus when ≥ 3 tools agree (same risk)
    -  5% per tool that returned an error / missing

Risk Classification Thresholds
-------------------------------
    0–24   → LOW
    25–49  → MEDIUM
    50–74  → HIGH
    75–100 → CRITICAL
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Severity keyword priority (higher = more severe) for evidence sorting
# ---------------------------------------------------------------------------
_SEVERITY_KEYWORDS: Dict[str, int] = {
    "critical":        100,
    "compromised":      95,
    "credential":       90,
    "harvesting":       90,
    "impersonation":    85,
    "spoofing":         85,
    "malicious":        85,
    "phishing":         85,
    "dmarc":            80,
    "spf":              75,
    "dkim":             75,
    "suspicious":       70,
    "ip-based":         65,
    "ip based":         65,
    "shortened":        60,
    "brand":            60,
    "attachment":       55,
    "financial":        55,
    "qr":               55,
    "mismatch":         50,
    "excessive":        40,
    "routing":          30,
}

_RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

# Aggregation weights (must sum to 1.0)
_WEIGHTS: Dict[str, float] = {
    "header":  0.25,
    "url":     0.30,
    "domain":  0.20,
    "content": 0.25,
}


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class PhishingRiskToolInput(BaseModel):
    """Input schema for PhishingRiskTool."""

    header_analysis: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "JSON output dict from EmailHeaderAnalysisTool. "
            "Expected fields: success, header_score, risk, findings, recommendations."
        ),
    )
    url_analysis: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "JSON output dict from URLInspectionTool. "
            "Expected fields: success, url_score, risk, findings, recommendations."
        ),
    )
    domain_analysis: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "JSON output dict from DomainReputationTool. "
            "Expected fields: success, trust_score, risk, findings, recommendations."
        ),
    )
    content_analysis: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "JSON output dict from ContentAnalysisTool. "
            "Expected fields: success, content_score, risk, findings, recommendations."
        ),
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class PhishingRiskTool(BaseTool):
    """
    Unified enterprise phishing risk aggregator.

    Fuses outputs from EmailHeaderAnalysisTool, URLInspectionTool,
    DomainReputationTool, and ContentAnalysisTool using a weighted scoring
    model to produce an authoritative phishing risk verdict and enterprise report.
    """

    name: str = "Phishing Risk Tool"
    description: str = (
        "Aggregates outputs from EmailHeaderAnalysisTool, URLInspectionTool, "
        "DomainReputationTool, and ContentAnalysisTool to produce a unified "
        "0–100 phishing risk score (LOW/MEDIUM/HIGH/CRITICAL) with confidence, "
        "merged evidence, prioritised recommendations, and an executive summary."
    )
    args_schema: Type[BaseModel] = PhishingRiskToolInput

    # -----------------------------------------------------------------------
    # ── PUBLIC ENTRY POINT ──────────────────────────────────────────────────
    # -----------------------------------------------------------------------

    def _run(
        self,
        header_analysis:  Dict[str, Any] = None,
        url_analysis:     Dict[str, Any] = None,
        domain_analysis:  Dict[str, Any] = None,
        content_analysis: Dict[str, Any] = None,
    ) -> str:
        """Execute unified phishing risk aggregation pipeline."""
        header_analysis  = header_analysis  or {}
        url_analysis     = url_analysis     or {}
        domain_analysis  = domain_analysis  or {}
        content_analysis = content_analysis or {}

        logger.info(
            "PhishingRiskTool: aggregating — header=%s url=%s domain=%s content=%s",
            bool(header_analysis), bool(url_analysis),
            bool(domain_analysis), bool(content_analysis),
        )

        try:
            # ── Step 1: Extract per-tool scores ────────────────────────────
            scores  = self._extract_scores(
                header_analysis, url_analysis, domain_analysis, content_analysis
            )

            # ── Step 2: Compute weighted aggregate score ────────────────────
            phishing_score = self._compute_aggregate_score(scores)

            # ── Step 3: Classify overall risk ──────────────────────────────
            overall_risk = self._classify_risk(phishing_score)

            # ── Step 4: Confidence engine ───────────────────────────────────
            confidence = self._compute_confidence(
                scores, header_analysis, url_analysis, domain_analysis, content_analysis
            )

            # ── Step 5: Merge and deduplicate evidence ──────────────────────
            evidence = self._merge_evidence(
                header_analysis, url_analysis, domain_analysis, content_analysis
            )

            # ── Step 6: Merge and deduplicate recommendations ───────────────
            recommendations = self._merge_recommendations(
                phishing_score, overall_risk,
                header_analysis, url_analysis, domain_analysis, content_analysis,
            )

            # ── Step 7: Build dashboard ─────────────────────────────────────
            dashboard = self._build_dashboard(scores, phishing_score)

            # ── Step 8: Executive summary ───────────────────────────────────
            summary = self._generate_executive_summary(
                phishing_score=phishing_score,
                overall_risk=overall_risk,
                confidence=confidence,
                scores=scores,
                evidence=evidence,
            )

            result: Dict[str, Any] = {
                "success":          True,
                "overall_risk":     overall_risk,
                "phishing_score":   phishing_score,
                "confidence":       confidence,
                "dashboard":        dashboard,
                "evidence":         evidence,
                "recommendations":  recommendations,
                "executive_summary": summary,
                "error":            None,
            }

            logger.info(
                "PhishingRiskTool: complete — score=%d risk=%s confidence=%d",
                phishing_score, overall_risk, confidence,
            )
            return json.dumps(result, indent=2)

        except Exception as exc:  # pragma: no cover
            logger.exception("PhishingRiskTool: unexpected error — %s", exc)
            return json.dumps({
                "success":          False,
                "overall_risk":     "UNKNOWN",
                "phishing_score":   0,
                "confidence":       0,
                "dashboard":        {},
                "evidence":         [],
                "recommendations":  [],
                "executive_summary": "",
                "error":            str(exc),
            }, indent=2)

    # =========================================================================
    # ── SCORE EXTRACTION ──────────────────────────────────────────────────────
    # =========================================================================

    def _extract_scores(
        self,
        header:  Dict[str, Any],
        url:     Dict[str, Any],
        domain:  Dict[str, Any],
        content: Dict[str, Any],
    ) -> Dict[str, Optional[int]]:
        """
        Extract the numeric risk score from each tool's output.

        Domain Reputation Tool returns `trust_score` (higher = safer),
        which is inverted to produce `domain_score` (higher = riskier).
        """
        def _safe_int(d: Dict[str, Any], key: str, default: Optional[int] = None) -> Optional[int]:
            val = d.get(key)
            if val is None:
                return default
            try:
                return max(0, min(100, int(val)))
            except (TypeError, ValueError):
                return default

        header_score  = _safe_int(header,  "header_score")
        url_score     = _safe_int(url,     "url_score")

        # DomainReputationTool → trust_score (invert: risk = 100 - trust)
        trust_score   = _safe_int(domain, "trust_score")
        domain_score  = (100 - trust_score) if trust_score is not None else None

        content_score = _safe_int(content, "content_score")

        return {
            "header":  header_score,
            "url":     url_score,
            "domain":  domain_score,
            "content": content_score,
        }

    # =========================================================================
    # ── AGGREGATE SCORE ───────────────────────────────────────────────────────
    # =========================================================================

    def _compute_aggregate_score(self, scores: Dict[str, Optional[int]]) -> int:
        """
        Compute a weighted average phishing score from available tool scores.
        If a tool's result is missing, redistribute its weight proportionally
        across the remaining tools so the total weight always sums to 1.0.
        """
        available: Dict[str, int] = {k: v for k, v in scores.items() if v is not None}
        if not available:
            return 0

        total_weight = sum(_WEIGHTS[k] for k in available)
        if total_weight == 0:
            return 0

        weighted_sum = sum(_WEIGHTS[k] * v for k, v in available.items())
        return round(weighted_sum / total_weight)

    # =========================================================================
    # ── RISK CLASSIFICATION ───────────────────────────────────────────────────
    # =========================================================================

    def _classify_risk(self, score: int) -> str:
        """Map 0–100 phishing score to risk label."""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        return "LOW"

    # =========================================================================
    # ── CONFIDENCE ENGINE ─────────────────────────────────────────────────────
    # =========================================================================

    def _compute_confidence(
        self,
        scores:   Dict[str, Optional[int]],
        header:   Dict[str, Any],
        url:      Dict[str, Any],
        domain:   Dict[str, Any],
        content:  Dict[str, Any],
    ) -> int:
        """
        Confidence model:
            Base:         50
            +10 per tool that returned a valid result    (max +40)
            + 8 per tool whose individual risk ≥ HIGH   (max +32)
            + 5 bonus when ≥ 3 tools agree on same risk tier
            - 5 per tool that returned error/missing
        """
        base = 50
        bonus = 0

        tool_data = {
            "header":  header,
            "url":     url,
            "domain":  domain,
            "content": content,
        }
        tool_risks: List[str] = []

        for key, data in tool_data.items():
            if data and data.get("success"):
                bonus += 10
                risk_val = data.get("risk", "LOW")
                if _RISK_ORDER.get(risk_val, 0) >= _RISK_ORDER["HIGH"]:
                    bonus += 8
                tool_risks.append(risk_val)
            else:
                bonus -= 5  # missing or errored tool

        # Agreement bonus: ≥ 3 tools in the same risk tier
        if len(tool_risks) >= 3:
            from collections import Counter
            most_common_risk, count = Counter(tool_risks).most_common(1)[0]
            if count >= 3:
                bonus += 5

        confidence = max(0, min(99, base + bonus))
        return confidence

    # =========================================================================
    # ── EVIDENCE AGGREGATION ──────────────────────────────────────────────────
    # =========================================================================

    def _merge_evidence(
        self,
        header:   Dict[str, Any],
        url:      Dict[str, Any],
        domain:   Dict[str, Any],
        content:  Dict[str, Any],
    ) -> List[str]:
        """
        Collect findings from all tools, remove duplicates (case-insensitive
        prefix deduplication), and sort by severity priority.
        """
        raw: List[str] = []

        for tool_data in (header, url, domain, content):
            findings = tool_data.get("findings", []) if tool_data else []
            for item in findings:
                if isinstance(item, str) and item.strip():
                    raw.append(item.strip())

        # Deduplicate by normalised prefix (first 60 chars, lower)
        seen: Set[str] = set()
        deduped: List[str] = []
        for item in raw:
            key = item.lower()[:60]
            if key not in seen:
                seen.add(key)
                deduped.append(item)

        # Sort by severity score (descending)
        def _severity(text: str) -> int:
            t = text.lower()
            return max((score for kw, score in _SEVERITY_KEYWORDS.items() if kw in t), default=0)

        deduped.sort(key=_severity, reverse=True)
        return deduped

    # =========================================================================
    # ── RECOMMENDATIONS ───────────────────────────────────────────────────────
    # =========================================================================

    def _merge_recommendations(
        self,
        score:    int,
        risk:     str,
        header:   Dict[str, Any],
        url:      Dict[str, Any],
        domain:   Dict[str, Any],
        content:  Dict[str, Any],
    ) -> List[str]:
        """
        Build a prioritised, deduplicated recommendation list combining
        tool-specific guidance with risk-level global actions.
        """
        recs: List[str] = []
        seen: Set[str] = set()

        def _add(text: str) -> None:
            key = text.lower()[:70]
            if key not in seen:
                seen.add(key)
                recs.append(text)

        # ── Global actions by risk tier ────────────────────────────────────
        if risk in ("CRITICAL", "HIGH"):
            _add("Quarantine the email immediately and prevent recipient delivery.")
            _add("Block the sender address and sending domain at the email gateway.")
            _add("Notify the recipient — do not click links, open attachments, or reply.")
            _add("Escalate to the Security Operations Centre (SOC) for incident response.")
        elif risk == "MEDIUM":
            _add("Hold the email in quarantine pending manual review.")
            _add("Warn the recipient and advise caution before interacting.")
        else:
            _add("Continue routine monitoring — no immediate action required.")

        # ── Tool-specific recommendations ──────────────────────────────────
        for tool_data in (header, url, domain, content):
            for rec in (tool_data.get("recommendations", []) if tool_data else []):
                if isinstance(rec, str) and rec.strip():
                    _add(rec.strip())

        # ── Conditional contextual actions ────────────────────────────────
        content_dash = content.get("dashboard", {}) if content else {}
        if content_dash.get("credential_requests", 0) > 0:
            _add(
                "If the recipient has already interacted: immediately reset credentials "
                "and invalidate all active sessions."
            )
        if content_dash.get("brand_link_mismatch"):
            _add("Report brand impersonation to the affected brand's abuse/phishing team.")
        if content_dash.get("suspicious_links", 0) > 0:
            _add(
                "Expand and submit all suspicious URLs to threat intelligence platforms "
                "(VirusTotal, URLhaus, PhishTank)."
            )
        if content_dash.get("attachment_lures", 0) > 0:
            _add("Sandbox-detonate any referenced attachments before allowing access.")
        if content_dash.get("qr_phishing"):
            _add("Extract and safely inspect QR code URL — do not scan with personal device.")

        if risk in ("CRITICAL", "HIGH"):
            _add("Submit all extracted IoCs (URLs, domains, IPs, hashes) to threat intelligence feeds.")
            _add("Scan endpoints that received this email for post-exploitation indicators.")

        return recs

    # =========================================================================
    # ── DASHBOARD ─────────────────────────────────────────────────────────────
    # =========================================================================

    def _build_dashboard(
        self,
        scores:         Dict[str, Optional[int]],
        overall_score:  int,
    ) -> Dict[str, Any]:
        """Build the telemetry dashboard dict."""
        return {
            "header_score":   scores.get("header"),
            "url_score":      scores.get("url"),
            "domain_score":   scores.get("domain"),
            "content_score":  scores.get("content"),
            "overall_score":  overall_score,
        }

    # =========================================================================
    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    # =========================================================================

    def _generate_executive_summary(
        self,
        phishing_score: int,
        overall_risk:   str,
        confidence:     int,
        scores:         Dict[str, Optional[int]],
        evidence:       List[str],
    ) -> str:
        """Generate a concise, enterprise-grade executive summary."""

        if phishing_score == 0:
            return (
                "Phishing risk assessment identified no significant indicators across email headers, "
                "URL inspection, domain reputation, and content analysis. "
                "The email passes baseline security checks."
            )

        # Identify which tool layers fired
        fired_layers: List[str] = []
        if scores.get("header") is not None and scores["header"] >= 25:  # type: ignore[operator]
            fired_layers.append("email header authentication failures")
        if scores.get("url") is not None and scores["url"] >= 25:  # type: ignore[operator]
            fired_layers.append("malicious or suspicious URL characteristics")
        if scores.get("domain") is not None and scores["domain"] >= 25:  # type: ignore[operator]
            fired_layers.append("low-reputation or newly registered domain")
        if scores.get("content") is not None and scores["content"] >= 25:  # type: ignore[operator]
            fired_layers.append("phishing content indicators (social engineering/credential harvesting)")

        layers_str = (
            ", ".join(fired_layers[:-1]) + f", and {fired_layers[-1]}"
            if len(fired_layers) > 1
            else (fired_layers[0] if fired_layers else "multiple phishing characteristics")
        )

        verdict_prefix = {
            "CRITICAL": f"HIGH-CONFIDENCE PHISHING DETECTED — Phishing score: {phishing_score}/100 (CRITICAL, confidence: {confidence}%). ",
            "HIGH":     f"Phishing assessment returned HIGH risk (score: {phishing_score}/100, confidence: {confidence}%). ",
            "MEDIUM":   f"Phishing assessment returned MEDIUM risk (score: {phishing_score}/100, confidence: {confidence}%). ",
            "LOW":      f"Phishing assessment returned LOW risk (score: {phishing_score}/100). ",
        }.get(overall_risk, f"Phishing score: {phishing_score}/100 ({overall_risk}). ")

        body = (
            f"The analyzed email exhibits multiple independent phishing indicators "
            f"across {len(fired_layers)} detection layer(s): {layers_str}. "
        )

        verdict_suffix = {
            "CRITICAL": (
                "The message should be treated as confirmed malicious and handled immediately. "
                "Quarantine, block all associated domains and URLs, notify the recipient, "
                "and initiate security incident response procedures."
            ),
            "HIGH": (
                "The email should be quarantined and the sender blocked pending a full investigation. "
                "Do not interact with any embedded links or attachments."
            ),
            "MEDIUM": (
                "Exercise caution. The email should be held for manual review "
                "before delivery to the recipient."
            ),
            "LOW": (
                "No immediate action required, but continue monitoring for escalation."
            ),
        }.get(overall_risk, "")

        return verdict_prefix + body + verdict_suffix
