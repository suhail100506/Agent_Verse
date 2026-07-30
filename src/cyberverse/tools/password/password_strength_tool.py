"""
PasswordStrengthTool — Enterprise Password Strength Analyser
============================================================
Evaluates password strength using entropy analysis, character diversity checks,
pattern detection, and common password identification.

SECURITY NOTICE:
    - Passwords are NEVER logged, stored, or included in error messages.
    - All analysis is performed in-memory only.
    - Log output contains only metadata (score, risk, length) — never the password.

Scoring Model (penalty-based, starting from 100)
-------------------------------------------------
    Length < 8 chars           → −30
    Length 8–11 chars          → −15
    Length 12–15 chars         → −0   (baseline)
    Length ≥ 16 chars          → +5   (bonus)
    No uppercase letters       → −10
    No lowercase letters       → −10
    No digits                  → −10
    No symbols                 → −10
    Has Unicode characters     → +5   (bonus)
    Entropy < 28 bits          → −25
    Entropy 28–50 bits         → −10
    Sequential chars (abc,123) → −15
    Keyboard walk (qwerty)     → −15
    Repeated chars (aaa,111)   → −10
    Date/year pattern          → −10
    Common password match      → −40
    zxcvbn score = 0           → −20  (if available)
    zxcvbn score = 1           → −10  (if available)

Risk Classification
-------------------
    80 – 100  → LOW      (strong password)
    50 – 79   → MEDIUM   (acceptable, improvable)
    25 – 49   → HIGH     (weak — improvement required)
    0  – 24   → CRITICAL (extremely weak — must change immediately)
"""

import re
import json
import math
import logging
import string
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# ---------------------------------------------------------------------------
# Optional dependency: zxcvbn
# ---------------------------------------------------------------------------
try:
    import zxcvbn as _zxcvbn_lib
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── CONSTANTS ───────────────────────────────────────────────────────────────
# ===========================================================================

# Top-100 most frequently breached passwords (HIBP / SecLists)
_COMMON_PASSWORDS: Set[str] = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234567", "111111", "1234567890", "123123", "abc123", "password1",
    "1234", "iloveyou", "admin", "letmein", "monkey", "login", "master",
    "dragon", "pass", "qwerty123", "000000", "654321", "superman",
    "1qaz2wsx", "7777777", "121212", "welcome", "sunshine", "password123",
    "shadow", "princess", "azerty", "trustno1", "passw0rd", "p@ssword",
    "passw0rd!", "p@ssw0rd", "p@ssword1", "admin123", "root", "toor",
    "test", "test123", "guest", "changeme", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "qwerty1", "password2", "hunter2", "solo", "starwars",
    "michael", "jennifer", "jessica", "joshua", "andrew", "thomas",
    "charlie", "summer", "batman", "football", "baseball", "soccer",
    "hockey", "harley", "ranger", "donald", "george", "jordan", "taylor",
    "access", "hello", "hello123", "master1", "!@#$%^&*", "zaq1zaq1",
    "qazwsx", "qweasdzxc", "qazxsw", "1q2w3e4r", "1q2w3e", "1q2w3e4r5t",
    "pass123", "secret", "winter2023", "spring2023", "summer2023",
    "winter2024", "spring2024", "summer2024", "company123", "welcome1",
    "january", "february", "march", "april", "monday", "password!",
}

# Keyboard walk sequences (rows and diagonals)
_KEYBOARD_SEQUENCES: List[str] = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
    "qweasdzxc", "1qaz2wsx", "qazwsx", "qazxsw", "1qaz", "2wsx",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    "1234", "12345", "123456", "1234567", "12345678", "123456789",
    "0987654321", "9876", "98765", "987654",
    "abcdef", "abcdefg", "abcdefgh", "zyxwvu",
]

# Sequential character groups for pattern checking
_SEQUENTIAL_SETS: List[str] = [
    string.ascii_lowercase,         # abcdefghijklmnopqrstuvwxyz
    string.ascii_uppercase,         # ABCDEFGHIJKLMNOPQRSTUVWXYZ
    string.digits,                  # 0123456789
    "9876543210",                   # reverse digits
]

# Date-like regex patterns
_DATE_PATTERNS: List[str] = [
    r"\b(19|20)\d{2}\b",                         # years 1900–2099
    r"\b\d{2}[/-]\d{2}[/-]\d{2,4}\b",           # DD/MM/YY or DD-MM-YYYY
    r"\b\d{4}[/-]\d{2}[/-]\d{2}\b",             # YYYY-MM-DD
    r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{2,4}\b",  # MonYYYY
    r"\b\d{2}(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b",    # DDMon
]


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordStrengthToolInput(BaseModel):
    """Input schema for PasswordStrengthTool."""

    password: str = Field(
        ...,
        description=(
            "Plaintext password string to evaluate. "
            "Never stored or logged — all analysis is in-memory only."
        ),
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class PasswordStrengthTool(BaseTool):
    """
    Enterprise password strength analyser.

    Evaluates password entropy, character diversity, pattern vulnerabilities,
    and common password matching. Produces a 0–100 password score, risk
    classification, structured findings, and actionable recommendations.

    SECURITY: Passwords are never logged, stored, or transmitted.
    """

    name: str = "Password Strength Tool"
    description: str = (
        "Evaluates password strength using Shannon entropy, character diversity "
        "(uppercase, lowercase, digits, symbols, Unicode), sequential and keyboard-walk "
        "pattern detection, common password matching, and date/year pattern analysis. "
        "Returns a 0–100 password score with risk level (LOW/MEDIUM/HIGH/CRITICAL), "
        "findings, and recommendations. Passwords are never logged or stored."
    )
    args_schema: Type[BaseModel] = PasswordStrengthToolInput

    # -----------------------------------------------------------------------
    # ── PUBLIC ENTRY POINT ──────────────────────────────────────────────────
    # -----------------------------------------------------------------------

    def _run(self, password: str = "") -> str:
        """
        Execute full password strength analysis pipeline.
        Password is NEVER included in any log output.
        """
        # ── Input validation ───────────────────────────────────────────────
        if not password or not isinstance(password, str):
            return json.dumps({
                "success":          False,
                "password_score":   0,
                "risk":             "CRITICAL",
                "dashboard":        {},
                "findings":         ["No password provided."],
                "recommendations":  ["Provide a non-empty password for analysis."],
                "error":            "Password must be a non-empty string.",
            }, indent=2)

        # Log only metadata — never the password itself
        logger.info(
            "PasswordStrengthTool: analysing — length=%d",
            len(password),
        )

        try:
            # ── Step 1: Character diversity ────────────────────────────────
            diversity = self._analyse_character_diversity(password)

            # ── Step 2: Entropy ────────────────────────────────────────────
            entropy_bits = self._calculate_entropy(password, diversity["charset_size"])

            # ── Step 3: Pattern detection ──────────────────────────────────
            patterns = self._detect_patterns(password)

            # ── Step 4: Common password check ─────────────────────────────
            is_common = self._check_common_passwords(password)

            # ── Step 5: zxcvbn auxiliary (optional) ───────────────────────
            zxcvbn_data = self._run_zxcvbn(password)

            # ── Step 6: Score engine ───────────────────────────────────────
            password_score = self._score_password(
                password=password,
                diversity=diversity,
                entropy_bits=entropy_bits,
                patterns=patterns,
                is_common=is_common,
                zxcvbn_data=zxcvbn_data,
            )

            # ── Step 7: Risk classification ────────────────────────────────
            risk = self._classify_risk(password_score)

            # ── Step 8: Findings + recommendations ────────────────────────
            findings:        List[str] = []
            recommendations: List[str] = []
            self._collect_findings_and_recommendations(
                password=password,
                diversity=diversity,
                entropy_bits=entropy_bits,
                patterns=patterns,
                is_common=is_common,
                zxcvbn_data=zxcvbn_data,
                password_score=password_score,
                risk=risk,
                findings=findings,
                recommendations=recommendations,
            )

            # ── Step 9: Dashboard ──────────────────────────────────────────
            dashboard = self._build_dashboard(
                password=password,
                diversity=diversity,
                entropy_bits=entropy_bits,
                patterns=patterns,
                is_common=is_common,
                password_score=password_score,
            )

            logger.info(
                "PasswordStrengthTool: complete — score=%d risk=%s entropy=%.1f bits",
                password_score, risk, entropy_bits,
            )

            return json.dumps({
                "success":          True,
                "password_score":   password_score,
                "risk":             risk,
                "dashboard":        dashboard,
                "findings":         findings,
                "recommendations":  recommendations,
                "error":            None,
            }, indent=2)

        except Exception as exc:
            # Suppress password from exception output
            logger.error(
                "PasswordStrengthTool: unexpected error (password suppressed) — %s",
                type(exc).__name__,
            )
            return json.dumps({
                "success":          False,
                "password_score":   0,
                "risk":             "CRITICAL",
                "dashboard":        {},
                "findings":         ["Analysis failed due to an internal error."],
                "recommendations":  ["Contact security team for manual review."],
                "error":            f"Analysis error: {type(exc).__name__}",
            }, indent=2)

    # =========================================================================
    # ── ANALYSIS MODULES ──────────────────────────────────────────────────────
    # =========================================================================

    # ── 1. Character Diversity ────────────────────────────────────────────────

    def _analyse_character_diversity(self, pwd: str) -> Dict[str, Any]:
        """
        Evaluate character set composition and compute pool size.

        Pool sizes:
            Lowercase a–z:  26
            Uppercase A–Z:  26
            Digits 0–9:     10
            Symbols (!@#…): 32
            Unicode (>127): 64  (approximate)
        """
        has_lower   = bool(re.search(r"[a-z]", pwd))
        has_upper   = bool(re.search(r"[A-Z]", pwd))
        has_digit   = bool(re.search(r"[0-9]", pwd))
        has_symbol  = bool(re.search(r"[^a-zA-Z0-9\s]", pwd) and
                           not all(ord(c) > 127 for c in re.findall(r"[^a-zA-Z0-9\s]", pwd)))
        has_unicode = any(ord(c) > 127 for c in pwd)
        has_space   = " " in pwd

        pool = 0
        if has_lower:   pool += 26
        if has_upper:   pool += 26
        if has_digit:   pool += 10
        if has_symbol:  pool += 32
        if has_unicode: pool += 64
        if has_space:   pool += 1

        char_types = sum([has_lower, has_upper, has_digit, has_symbol, has_unicode])

        return {
            "length":       len(pwd),
            "has_upper":    has_upper,
            "has_lower":    has_lower,
            "has_digit":    has_digit,
            "has_symbol":   has_symbol,
            "has_unicode":  has_unicode,
            "has_space":    has_space,
            "charset_size": max(pool, 1),
            "char_types":   char_types,   # number of distinct character categories used
        }

    # ── 2. Entropy Calculation ────────────────────────────────────────────────

    def _calculate_entropy(self, pwd: str, charset_size: int) -> float:
        """
        Calculate Shannon entropy using the pool-size model:
            H = length × log₂(charset_size)

        This is an upper-bound estimate. Pattern-matched passwords
        will have their effective entropy reduced by the scoring penalties.
        """
        if charset_size <= 1:
            return 0.0
        return round(len(pwd) * math.log2(charset_size), 1)

    # ── 3. Pattern Detection ──────────────────────────────────────────────────

    def _detect_patterns(self, pwd: str) -> Dict[str, Any]:
        """
        Detect structural weaknesses:
        - Sequential characters (abc, 123)
        - Keyboard walks (qwerty, asdf)
        - Repeated characters (aaa, !!!!)
        - Date or year patterns (2024, 01/01/2000)
        """
        lower_pwd = pwd.lower()

        # ── Sequential characters ──────────────────────────────────────────
        sequential = False
        for seq in _SEQUENTIAL_SETS:
            for run_len in range(4, min(len(pwd) + 1, 10)):
                for i in range(len(seq) - run_len + 1):
                    if seq[i: i + run_len].lower() in lower_pwd:
                        sequential = True
                        break
                    if seq[i: i + run_len][::-1].lower() in lower_pwd:
                        sequential = True
                        break
                if sequential:
                    break
            if sequential:
                break

        # ── Keyboard walks ─────────────────────────────────────────────────
        keyboard_walk = False
        for kseq in _KEYBOARD_SEQUENCES:
            if len(kseq) >= 4 and kseq in lower_pwd:
                keyboard_walk = True
                break
            if len(kseq) >= 4 and kseq[::-1] in lower_pwd:
                keyboard_walk = True
                break

        # ── Repeated characters ────────────────────────────────────────────
        # Triggers if any character appears ≥ 3 consecutive times
        # or if any character makes up > 50% of the password
        repeated = bool(re.search(r"(.)\1{2,}", pwd))
        if not repeated:
            char_counts = Counter(pwd.lower())
            most_common_freq = char_counts.most_common(1)[0][1] / len(pwd)
            if most_common_freq > 0.5 and len(pwd) > 4:
                repeated = True

        # ── Date / year patterns ───────────────────────────────────────────
        date_pattern = any(
            re.search(p, lower_pwd, re.I) for p in _DATE_PATTERNS
        )

        return {
            "sequential":    sequential,
            "keyboard_walk": keyboard_walk,
            "repeated_chars": repeated,
            "date_pattern":  date_pattern,
        }

    # ── 4. Common Password Check ──────────────────────────────────────────────

    def _check_common_passwords(self, pwd: str) -> bool:
        """
        Check whether the password (case-insensitive) appears in the embedded
        common password list. No external API calls are made.
        """
        return pwd.lower() in _COMMON_PASSWORDS or pwd in _COMMON_PASSWORDS

    # ── 5. zxcvbn (Optional) ─────────────────────────────────────────────────

    def _run_zxcvbn(self, pwd: str) -> Optional[Dict[str, Any]]:
        """
        Run zxcvbn analysis if available.
        Returns the zxcvbn result dict, or None if not installed.
        """
        if not HAS_ZXCVBN:
            return None
        try:
            result = _zxcvbn_lib.zxcvbn(pwd)
            return {
                "score":            int(result.get("score", 0)),
                "guesses_log10":    result.get("guesses_log10", 0),
                "crack_time_offline": str(
                    result.get("crack_times_display", {})
                    .get("offline_fast_hashing_1e10_per_second", "unknown")
                ),
                "crack_time_online": str(
                    result.get("crack_times_display", {})
                    .get("online_no_throttling_10_per_second", "unknown")
                ),
                "warning":          result.get("feedback", {}).get("warning", ""),
                "suggestions":      result.get("feedback", {}).get("suggestions", []),
            }
        except Exception:
            return None

    # =========================================================================
    # ── SCORE ENGINE ──────────────────────────────────────────────────────────
    # =========================================================================

    def _score_password(
        self,
        password:     str,
        diversity:    Dict[str, Any],
        entropy_bits: float,
        patterns:     Dict[str, Any],
        is_common:    bool,
        zxcvbn_data:  Optional[Dict[str, Any]],
    ) -> int:
        """
        Compute a 0–100 password score using a penalty model starting from 100.

        Penalties are additive. Bonuses are applied before clamping to 0–100.
        """
        score = 100
        length = diversity["length"]

        # ── Length penalties / bonus ───────────────────────────────────────
        if length < 6:
            score -= 40
        elif length < 8:
            score -= 30
        elif length < 12:
            score -= 15
        elif length >= 16:
            score += 5    # bonus for ≥16 chars
        if length >= 20:
            score += 3    # additional bonus for ≥20 chars

        # ── Character diversity penalties ──────────────────────────────────
        if not diversity["has_upper"]:   score -= 10
        if not diversity["has_lower"]:   score -= 10
        if not diversity["has_digit"]:   score -= 10
        if not diversity["has_symbol"]:  score -= 10

        # ── Unicode bonus ──────────────────────────────────────────────────
        if diversity["has_unicode"]:     score += 5

        # ── Entropy penalties ──────────────────────────────────────────────
        if entropy_bits < 28:
            score -= 25
        elif entropy_bits < 50:
            score -= 10
        elif entropy_bits >= 80:
            score += 5    # bonus for very high entropy

        # ── Pattern penalties ──────────────────────────────────────────────
        if patterns["sequential"]:       score -= 15
        if patterns["keyboard_walk"]:    score -= 15
        if patterns["repeated_chars"]:   score -= 10
        if patterns["date_pattern"]:     score -= 10

        # ── Common password penalty (severe) ──────────────────────────────
        if is_common:
            score -= 40

        # ── zxcvbn auxiliary adjustment ────────────────────────────────────
        if zxcvbn_data is not None:
            zx_score = zxcvbn_data.get("score", 2)
            if zx_score == 0:
                score -= 20
            elif zx_score == 1:
                score -= 10
            elif zx_score == 4:
                score += 5    # zxcvbn considers it very strong

        return max(0, min(100, score))

    # =========================================================================
    # ── RISK CLASSIFICATION ───────────────────────────────────────────────────
    # =========================================================================

    def _classify_risk(self, score: int) -> str:
        """Map 0–100 password score to risk label (lower score = higher risk)."""
        if score >= 80:
            return "LOW"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "HIGH"
        return "CRITICAL"

    # =========================================================================
    # ── FINDINGS & RECOMMENDATIONS ────────────────────────────────────────────
    # =========================================================================

    def _collect_findings_and_recommendations(
        self,
        password:        str,
        diversity:       Dict[str, Any],
        entropy_bits:    float,
        patterns:        Dict[str, Any],
        is_common:       bool,
        zxcvbn_data:     Optional[Dict[str, Any]],
        password_score:  int,
        risk:            str,
        findings:        List[str],
        recommendations: List[str],
    ) -> None:
        """Populate findings and recommendations lists in-place."""
        length = diversity["length"]

        # ── Length findings ────────────────────────────────────────────────
        if length < 8:
            findings.append(f"Password length ({length} chars) is critically short — below the 8-character minimum.")
            recommendations.append("Increase password length to at least 16 characters.")
        elif length < 12:
            findings.append(f"Password length ({length} chars) is below the recommended 12-character baseline.")
            recommendations.append("Increase password length to at least 12–16 characters.")
        elif length < 16:
            recommendations.append("Consider increasing password length to 16+ characters for additional security.")

        # ── Character diversity findings ───────────────────────────────────
        missing = []
        if not diversity["has_upper"]:   missing.append("uppercase letters")
        if not diversity["has_lower"]:   missing.append("lowercase letters")
        if not diversity["has_digit"]:   missing.append("digits")
        if not diversity["has_symbol"]:  missing.append("symbols (!@#$%^&*)")

        if missing:
            findings.append(f"Password is missing character types: {', '.join(missing)}.")
            if not diversity["has_symbol"]:
                recommendations.append("Add special symbols (e.g., !@#$%^&*) to significantly increase entropy.")
            if not diversity["has_upper"]:
                recommendations.append("Include at least one uppercase letter.")
            if not diversity["has_digit"]:
                recommendations.append("Include at least one digit.")

        # ── Entropy findings ───────────────────────────────────────────────
        if entropy_bits < 28:
            findings.append(
                f"Password entropy is critically low ({entropy_bits:.1f} bits) — "
                "highly vulnerable to brute-force and dictionary attacks."
            )
        elif entropy_bits < 50:
            findings.append(
                f"Password entropy is moderate ({entropy_bits:.1f} bits) — "
                "could be cracked with targeted offline attacks."
            )

        # ── Pattern findings ───────────────────────────────────────────────
        if patterns["sequential"]:
            findings.append("Sequential character sequence detected (e.g., abc, 123).")
            recommendations.append("Avoid sequential characters (abc, 123, xyz).")

        if patterns["keyboard_walk"]:
            findings.append("Keyboard walk pattern detected (e.g., qwerty, asdf).")
            recommendations.append("Avoid keyboard walk patterns (qwerty, asdfgh, 1qaz2wsx).")

        if patterns["repeated_chars"]:
            findings.append("Repeated character pattern detected (e.g., aaa, !!!!, 111).")
            recommendations.append("Avoid repeating the same character multiple times consecutively.")

        if patterns["date_pattern"]:
            findings.append("Date or year pattern detected — personal information increases guessability.")
            recommendations.append("Avoid using dates, years, or birth dates in passwords.")

        # ── Common password findings ───────────────────────────────────────
        if is_common:
            findings.append(
                "Password matches a known breached/common password list. "
                "This password is trivially guessable."
            )
            recommendations.append(
                "This password has appeared in data breach lists. "
                "Change it immediately to a unique, randomly generated password."
            )

        # ── zxcvbn auxiliary findings ──────────────────────────────────────
        if zxcvbn_data:
            if zxcvbn_data.get("warning"):
                findings.append(f"Pattern analysis warning: {zxcvbn_data['warning']}")
            for suggestion in zxcvbn_data.get("suggestions", []):
                if suggestion not in recommendations:
                    recommendations.append(suggestion)

        # ── Universal recommendations ──────────────────────────────────────
        recommendations.append("Use a reputable password manager to generate and store strong passwords.")

        if not findings:
            findings.append(
                f"Password meets baseline strength requirements "
                f"(score: {password_score}/100, entropy: {entropy_bits:.1f} bits)."
            )

        if risk in ("LOW",) and password_score >= 80:
            recommendations.append(
                "Enable multi-factor authentication (MFA) as an additional security layer."
            )

        # ── Deduplicate ────────────────────────────────────────────────────
        seen_f: List[str] = []
        for f in findings:
            if f not in seen_f:
                seen_f.append(f)
        findings[:] = seen_f

        seen_r: List[str] = []
        for r in recommendations:
            if r not in seen_r:
                seen_r.append(r)
        recommendations[:] = seen_r

    # =========================================================================
    # ── DASHBOARD ─────────────────────────────────────────────────────────────
    # =========================================================================

    def _build_dashboard(
        self,
        password:     str,
        diversity:    Dict[str, Any],
        entropy_bits: float,
        patterns:     Dict[str, Any],
        is_common:    bool,
        password_score: int,
    ) -> Dict[str, Any]:
        """Build the telemetry dashboard (never includes the password)."""
        # Estimate crack time tier from entropy
        if entropy_bits >= 100:
            crack_time = "centuries"
        elif entropy_bits >= 80:
            crack_time = "years"
        elif entropy_bits >= 60:
            crack_time = "months"
        elif entropy_bits >= 45:
            crack_time = "days"
        elif entropy_bits >= 35:
            crack_time = "hours"
        elif entropy_bits >= 25:
            crack_time = "minutes"
        else:
            crack_time = "instant"

        # Character type count for diversity indicator
        char_types = diversity["char_types"]
        diversity_label = (
            "excellent" if char_types >= 4
            else "good" if char_types == 3
            else "fair" if char_types == 2
            else "poor"
        )

        return {
            "length":           diversity["length"],
            "entropy_bits":     entropy_bits,
            "uppercase":        diversity["has_upper"],
            "lowercase":        diversity["has_lower"],
            "numbers":          diversity["has_digit"],
            "symbols":          diversity["has_symbol"],
            "unicode":          diversity["has_unicode"],
            "char_types":       char_types,
            "diversity":        diversity_label,
            "sequential":       patterns["sequential"],
            "keyboard_walk":    patterns["keyboard_walk"],
            "repeated_chars":   patterns["repeated_chars"],
            "date_pattern":     patterns["date_pattern"],
            "common_password":  is_common,
            "estimated_crack_time_offline": crack_time,
            "score":            password_score,
        }
