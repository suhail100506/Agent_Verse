"""
ContentAnalysisTool — Phishing Email Content Analyzer
======================================================
Analyzes email subject and body content to identify phishing attempts using
rule-based NLP, pattern matching, and social engineering detection heuristics.

Detection Engines
-----------------
1.  Content Extraction      — Parses plain text, HTML, and multipart emails.
2.  Social Engineering      — Urgency, fear, scarcity, authority, curiosity lures.
3.  Credential Harvesting   — Detects requests for passwords, OTP, PII, keys.
4.  Brand Impersonation     — Recognizes spoofed brands with mismatched links.
5.  Hyperlink Analysis      — IP links, shorteners, display-text mismatch, hidden URLs.
6.  Attachment Lures        — Dangerous file extension references in body.
7.  Financial Requests      — Payment, wire-transfer, invoice language.
8.  QR Code Phishing        — References to QR codes in email body.
9.  Risk Scoring Engine     — 0–100 weighted score → LOW/MEDIUM/HIGH/CRITICAL.
10. Executive Summary       — Concise enterprise-grade NL summary.

Scoring Model
-------------
    Urgency language        → +10
    Fear tactics            → +10
    Credential harvesting   → +25
    Brand impersonation     → +20
    Suspicious hyperlinks   → +15
    Attachment lure         → +15
    Financial request       → +20
    QR phishing reference   → +15

Risk Levels
-----------
    0  – 29   → LOW
    30 – 59   → MEDIUM
    60 – 79   → HIGH
    80 – 100  → CRITICAL
"""

import re
import html
import json
import logging
import ipaddress
import urllib.parse
from collections import Counter
from email import message_from_string
from typing import Any, Dict, List, Optional, Set, Tuple, Type

from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# ---------------------------------------------------------------------------
# Optional dependency: BeautifulSoup
# ---------------------------------------------------------------------------
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:  # pragma: no cover
    HAS_BS4 = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ===========================================================================
# ── CONSTANTS ───────────────────────────────────────────────────────────────
# ===========================================================================

# Social engineering phrase libraries
_URGENCY_PATTERNS: List[str] = [
    r"immediate(?:ly)?\s+action",
    r"act\s+now",
    r"respond\s+immediately",
    r"urgent(?:ly)?",
    r"as\s+soon\s+as\s+possible",
    r"asap",
    r"within\s+\d+\s+hours?",
    r"within\s+\d+\s+minutes?",
    r"deadline",
    r"time.?sensitive",
    r"don'?t\s+delay",
    r"expires?\s+(today|soon|in\s+\d+)",
    r"last\s+chance",
    r"final\s+(notice|warning|reminder)",
    r"action\s+required",
]

_FEAR_PATTERNS: List[str] = [
    r"account\s+(suspended|locked|disabled|compromised|breached|hacked)",
    r"unusual\s+(activity|login|sign.?in)",
    r"suspicious\s+(activity|login|access|behaviour|behavior)",
    r"unauthorized\s+(access|activity|login)",
    r"security\s+(alert|breach|incident|warning|threat|violation)",
    r"we\s+detected",
    r"we\s+(have\s+)?(noticed|found|identified)",
    r"your\s+account\s+(is\s+at\s+risk|will\s+be\s+(closed|terminated|suspended))",
    r"failure\s+to\s+(comply|respond|verify|confirm)",
    r"legal\s+(action|proceedings?)",
    r"law\s+enforcement",
]

_SCARCITY_PATTERNS: List[str] = [
    r"limited\s+time",
    r"limited\s+offer",
    r"only\s+\d+\s+(spots?|seats?|left|remaining|available)",
    r"exclusive\s+(offer|deal|access)",
    r"don'?t\s+miss\s+out",
    r"offer\s+expires?",
    r"while\s+supplies?\s+last",
]

_AUTHORITY_PATTERNS: List[str] = [
    r"your\s+(it\s+)?administrator",
    r"system\s+administrator",
    r"security\s+team",
    r"compliance\s+(team|department|officer)",
    r"hr\s+department",
    r"management",
    r"ceo|cfo|ciso|cto",
    r"support\s+team",
    r"helpdesk",
    r"technical\s+support",
    r"customer\s+service",
]

_CURIOSITY_PATTERNS: List[str] = [
    r"congratulations?",
    r"you(?:'ve|\s+have)\s+won",
    r"you(?:'ve|\s+have)\s+been\s+selected",
    r"claim\s+your\s+(prize|reward|gift)",
    r"free\s+(gift|reward|prize|offer)",
    r"lucky\s+winner",
    r"special\s+offer\s+for\s+you",
    r"click\s+here\s+to\s+(find\s+out|see|learn|discover)",
    r"secret\s+(deal|offer)",
]

# Credential and sensitive data harvesting
_CREDENTIAL_PATTERNS: List[Tuple[str, str]] = [
    (r"enter\s+your\s+password", "password"),
    (r"provide\s+your\s+password", "password"),
    (r"confirm\s+your\s+password", "password"),
    (r"reset\s+your\s+password", "password"),
    (r"enter\s+your\s+username", "username"),
    (r"provide\s+your\s+username", "username"),
    (r"one.?time\s+(password|code|pin)", "OTP"),
    (r"\botp\b", "OTP"),
    (r"verification\s+code", "OTP"),
    (r"enter\s+your\s+pin", "PIN"),
    (r"enter\s+your\s+credit\s+card", "credit card"),
    (r"card\s+number", "credit card"),
    (r"cvv", "CVV"),
    (r"expiry\s+date", "card expiry"),
    (r"bank\s+account\s+(number|details)", "banking credential"),
    (r"routing\s+number", "banking credential"),
    (r"social\s+security\s+number", "SSN"),
    (r"\bssn\b", "SSN"),
    (r"aadhaar\s+(number|card)", "Aadhaar"),
    (r"\baadhaar\b", "Aadhaar"),
    (r"pan\s+(card|number)", "PAN"),
    (r"passport\s+number", "passport"),
    (r"api\s+key", "API key"),
    (r"secret\s+key", "API key"),
    (r"access\s+token", "access token"),
    (r"recovery\s+code", "recovery code"),
    (r"backup\s+code", "recovery code"),
    (r"2fa\s+code", "2FA code"),
    (r"login\s+credentials", "credentials"),
    (r"sign\s*in\s+(below|here|now)", "login prompt"),
    (r"verify\s+your\s+identity", "identity verification"),
    (r"confirm\s+your\s+(account|details|information)", "account verification"),
]

# Brand impersonation detection
_BRANDS: Dict[str, List[str]] = {
    "Microsoft":  ["microsoft", "office365", "office 365", "outlook", "onedrive", "azure", "teams", "sharepoint"],
    "Google":     ["google", "gmail", "youtube", "google drive", "google docs", "google pay"],
    "Apple":      ["apple", "icloud", "itunes", "app store", "facetime"],
    "Amazon":     ["amazon", "aws", "prime", "amazon pay", "alexa"],
    "PayPal":     ["paypal", "pay pal"],
    "GitHub":     ["github", "git hub"],
    "Dropbox":    ["dropbox", "drop box"],
    "Netflix":    ["netflix"],
    "Facebook":   ["facebook", "meta", "fb.com"],
    "Instagram":  ["instagram"],
    "LinkedIn":   ["linkedin"],
    "Twitter":    ["twitter", "x.com"],
    "Slack":      ["slack"],
    "Zoom":       ["zoom"],
    "WhatsApp":   ["whatsapp"],
    "Telegram":   ["telegram"],
    "DHL":        ["dhl"],
    "FedEx":      ["fedex"],
    "UPS":        ["ups"],
    "IRS":        ["irs", "internal revenue"],
    "Bank":       ["chase", "wells fargo", "bank of america", "citibank", "barclays", "hsbc"],
}

# URL shortener domains
_URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "short.link", "shorturl.at", "rebrand.ly", "bl.ink", "tr.im",
    "snip.ly", "clk.sh", "cutt.ly", "tiny.cc", "rb.gy", "qr.ae",
}

# Suspicious TLDs commonly abused in phishing
_SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work", ".click",
    ".xyz", ".zip", ".mov", ".cam", ".men", ".review", ".download",
    ".racing", ".win", ".accountant", ".loan", ".party", ".date",
    ".faith", ".science", ".trade", ".country",
}

# Dangerous attachment extensions
_DANGEROUS_EXTENSIONS: List[Tuple[str, str]] = [
    (r"\b(invoice|receipt|statement)\b",                        "document lure"),
    (r"\bopen\s+the\s+(attached|attachment)\b",                 "attachment prompt"),
    (r"\bsee\s+(attached|attachment)\b",                        "attachment prompt"),
    (r"\.exe\b",                                                 "EXE file reference"),
    (r"\.zip\b",                                                 "ZIP file reference"),
    (r"\.rar\b",                                                 "RAR file reference"),
    (r"\.iso\b",                                                 "ISO file reference"),
    (r"\.docm\b",                                                "DOCM macro-enabled reference"),
    (r"\.xlsm\b",                                                "XLSM macro-enabled reference"),
    (r"\.pdf\b",                                                 "PDF file reference"),
    (r"\bpassword.?protected\s+(zip|rar|archive|file)\b",       "password-protected archive"),
]

# Financial request patterns
_FINANCIAL_PATTERNS: List[str] = [
    r"wire\s+transfer",
    r"send\s+(money|funds|payment|bitcoin|crypto)",
    r"gift\s+card",
    r"itunes?\s+(gift\s+)?card",
    r"google\s+play\s+card",
    r"amazon\s+gift\s+card",
    r"make\s+a\s+payment",
    r"pay\s+immediately",
    r"outstanding\s+(invoice|balance|amount|payment)",
    r"overdue\s+(invoice|payment|balance|account)",
    r"click\s+(here\s+)?to\s+pay",
    r"update\s+(billing|payment)\s+information",
    r"bitcoin|cryptocurrency|crypto\s+wallet",
    r"paymentfailed",
    r"payment\s+failed",
    r"payment\s+declined",
    r"your\s+invoice\s+is\s+(ready|attached|enclosed)",
]

# QR code phishing references
_QR_PATTERNS: List[str] = [
    r"scan\s+(the|this|our)?\s*qr\s+code",
    r"qr\s+code\s+(to|for|below)",
    r"scan\s+with\s+your\s+(phone|camera|device)",
    r"use\s+your\s+(phone|camera)\s+to\s+scan",
    r"qr\s+phish",
    r"image\s+below\s+to\s+(log\s*in|verify|claim)",
]


# ===========================================================================
# ── INPUT SCHEMA ────────────────────────────────────────────────────────────
# ===========================================================================

class ContentAnalysisToolInput(BaseModel):
    """Input schema for ContentAnalysisTool."""

    subject: str = Field(
        default="",
        description="Email subject line to analyze.",
    )
    body: str = Field(
        ...,
        description=(
            "Raw email body content. Accepts plain text, HTML markup, "
            "or raw RFC-2822 MIME message string."
        ),
    )


# ===========================================================================
# ── TOOL ────────────────────────────────────────────────────────────────────
# ===========================================================================

class ContentAnalysisTool(BaseTool):
    """
    Phishing email content analyzer.

    Applies rule-based NLP, pattern matching, and social engineering heuristics
    to identify phishing attempts in email subject and body content.
    Returns a 0–100 content risk score, structured findings, and an executive summary.
    """

    name: str = "Content Analysis Tool"
    description: str = (
        "Analyzes email subject and body content for phishing indicators including "
        "social engineering tactics, credential harvesting, brand impersonation, "
        "suspicious hyperlinks, dangerous attachment references, financial requests, "
        "and QR code phishing. Returns a 0–100 content risk score and enterprise-grade report."
    )
    args_schema: Type[BaseModel] = ContentAnalysisToolInput

    # -----------------------------------------------------------------------
    # ── PUBLIC ENTRY POINT ──────────────────────────────────────────────────
    # -----------------------------------------------------------------------

    def _run(self, subject: str = "", body: str = "") -> str:
        """Execute full phishing content analysis pipeline."""
        logger.info("ContentAnalysisTool: starting analysis — subject=%r (body length=%d)", subject, len(body))

        try:
            # ── Step 1: Extract and normalise content ──────────────────────
            extraction = self._extract_content(subject=subject, body=body)
            plain_text: str  = extraction["plain_text"]
            full_text: str   = extraction["full_text"]   # subject + plain_text (lower)
            links: List[Dict[str, str]] = extraction["links"]

            # ── Step 2: Run detection modules ──────────────────────────────
            social_eng   = self._detect_social_engineering(full_text)
            credentials  = self._detect_credential_harvesting(full_text)
            brands       = self._detect_brand_impersonation(full_text, links)
            hyperlinks   = self._analyze_hyperlinks(links, full_text)
            attachments  = self._detect_attachment_lures(full_text)
            financial    = self._detect_financial_requests(full_text)
            qr           = self._detect_qr_references(full_text)

            # ── Step 3: Score ───────────────────────────────────────────────
            score, risk, confidence = self._calculate_risk_score(
                social_eng=social_eng,
                credentials=credentials,
                brands=brands,
                hyperlinks=hyperlinks,
                attachments=attachments,
                financial=financial,
                qr=qr,
            )

            # ── Step 4: Aggregate findings and recommendations ──────────────
            findings:       List[str] = []
            recommendations: List[str] = []
            self._collect_findings(
                social_eng, credentials, brands, hyperlinks,
                attachments, financial, qr,
                findings, recommendations,
            )

            # ── Step 5: Build dashboard ─────────────────────────────────────
            dashboard: Dict[str, Any] = {
                "urgency_detected":      social_eng["urgency"],
                "fear_detected":         social_eng["fear"],
                "scarcity_detected":     social_eng["scarcity"],
                "authority_detected":    social_eng["authority"],
                "curiosity_detected":    social_eng["curiosity"],
                "credential_requests":   len(credentials["types"]),
                "credential_types":      credentials["types"],
                "brand_mentions":        list(brands["matched_brands"]),
                "brand_link_mismatch":   brands["link_mismatch"],
                "suspicious_links":      hyperlinks["suspicious_count"],
                "total_links":           hyperlinks["total_links"],
                "ip_based_links":        hyperlinks["ip_links"],
                "shortened_links":       hyperlinks["shortened_links"],
                "attachment_lures":      len(attachments["types"]),
                "attachment_types":      attachments["types"],
                "financial_request":     financial["detected"],
                "qr_phishing":           qr["detected"],
                "content_score":         score,
            }

            # ── Step 6: Executive summary ───────────────────────────────────
            summary = self._generate_executive_summary(
                score=score,
                risk=risk,
                social_eng=social_eng,
                credentials=credentials,
                brands=brands,
                hyperlinks=hyperlinks,
                attachments=attachments,
                financial=financial,
                qr=qr,
            )

            result: Dict[str, Any] = {
                "success":          True,
                "content_score":    score,
                "risk":             risk,
                "confidence":       confidence,
                "dashboard":        dashboard,
                "findings":         findings,
                "recommendations":  recommendations,
                "executive_summary": summary,
                "error":            None,
            }

            logger.info(
                "ContentAnalysisTool: complete — score=%d risk=%s confidence=%d",
                score, risk, confidence,
            )
            return json.dumps(result, indent=2)

        except Exception as exc:  # pragma: no cover
            logger.exception("ContentAnalysisTool: unexpected error — %s", exc)
            return json.dumps({
                "success":          False,
                "content_score":    0,
                "risk":             "UNKNOWN",
                "confidence":       0,
                "dashboard":        {},
                "findings":         [],
                "recommendations":  [],
                "executive_summary": "",
                "error":            str(exc),
            }, indent=2)

    # =========================================================================
    # ── DETECTION MODULES ─────────────────────────────────────────────────────
    # =========================================================================

    # ── 1. Content Extraction ─────────────────────────────────────────────────

    def _extract_content(self, subject: str, body: str) -> Dict[str, Any]:
        """
        Parse and normalise email body content.

        Supports plain text, raw HTML, and RFC-2822 MIME multipart messages.
        Extracts visible text and all embedded hyperlinks.

        Returns
        -------
        dict with keys:
            ``plain_text``  — normalised visible text from body
            ``full_text``   — lowercased concatenation of subject + plain_text
            ``links``       — list of dicts with 'text' and 'href' keys
        """
        links: List[Dict[str, str]] = []
        plain_text: str = ""

        if not body:
            return {"plain_text": "", "full_text": (subject or "").lower(), "links": []}

        # ── Attempt RFC-2822 MIME parsing first ────────────────────────────
        msg = message_from_string(body)
        if msg.get_content_type() not in (None, "") and msg.get_payload():
            plain_text, links = self._parse_mime_message(msg)
        else:
            # ── Heuristic: detect raw HTML vs plain text ───────────────────
            if re.search(r"<\s*html|<\s*body|<\s*div|<\s*p\b|<\s*a\s", body, re.I):
                plain_text, links = self._parse_html(body)
            else:
                plain_text = self._normalise_text(body)
                links = self._extract_markdown_links(body)

        full_text = f"{(subject or '')} {plain_text}".lower()
        return {
            "plain_text": plain_text,
            "full_text":  full_text,
            "links":      links,
        }

    def _parse_mime_message(self, msg: Any) -> Tuple[str, List[Dict[str, str]]]:
        """Recursively walk MIME message parts and collect text + links."""
        parts_text: List[str] = []
        links: List[Dict[str, str]] = []

        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/html":
                payload = self._safe_decode_payload(part)
                text, part_links = self._parse_html(payload)
                parts_text.append(text)
                links.extend(part_links)
            elif content_type == "text/plain":
                payload = self._safe_decode_payload(part)
                parts_text.append(self._normalise_text(payload))
                links.extend(self._extract_markdown_links(payload))

        return " ".join(filter(None, parts_text)), links

    def _parse_html(self, raw_html: str) -> Tuple[str, List[Dict[str, str]]]:
        """
        Parse HTML content using BeautifulSoup (preferred) or regex fallback.
        Extracts visible text and all <a href="..."> hyperlinks.
        """
        links: List[Dict[str, str]] = []

        if HAS_BS4:
            soup = BeautifulSoup(raw_html, "html.parser")

            # Collect links before removing tags
            for tag in soup.find_all("a", href=True):
                href: str = tag.get("href", "").strip()
                text: str = tag.get_text(strip=True)
                if href:
                    links.append({"text": text, "href": href})

            # Remove script / style noise
            for noise in soup(["script", "style", "head", "meta"]):
                noise.decompose()

            visible_text = soup.get_text(separator=" ")
        else:
            # Regex fallback — extract links manually
            for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', raw_html, re.I | re.S):
                links.append({"href": m.group(1).strip(), "text": re.sub(r"<[^>]+>", "", m.group(2)).strip()})
            # Strip all tags
            visible_text = re.sub(r"<[^>]+>", " ", raw_html)

        # Decode HTML entities and normalise whitespace
        visible_text = html.unescape(visible_text)
        return self._normalise_text(visible_text), links

    def _normalise_text(self, text: str) -> str:
        """Decode HTML entities, collapse whitespace, strip leading/trailing."""
        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _safe_decode_payload(self, part: Any) -> str:
        """Safely decode MIME part payload to str."""
        try:
            charset = part.get_content_charset() or "utf-8"
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload.decode(charset, errors="replace")
            return str(payload or "")
        except Exception:
            return ""

    def _extract_markdown_links(self, text: str) -> List[Dict[str, str]]:
        """Extract raw URLs from plain text using URL regex."""
        links = []
        url_re = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
        for url in url_re.findall(text):
            links.append({"text": "", "href": url})
        return links

    # ── 2. Social Engineering Detection ──────────────────────────────────────

    def _detect_social_engineering(self, text: str) -> Dict[str, Any]:
        """
        Detect social engineering language across five categories:
        urgency, fear, scarcity, authority impersonation, and curiosity bait.
        """
        def _match(patterns: List[str]) -> List[str]:
            return [p for p in patterns if re.search(p, text, re.I)]

        urgency_hits   = _match(_URGENCY_PATTERNS)
        fear_hits      = _match(_FEAR_PATTERNS)
        scarcity_hits  = _match(_SCARCITY_PATTERNS)
        authority_hits = _match(_AUTHORITY_PATTERNS)
        curiosity_hits = _match(_CURIOSITY_PATTERNS)

        return {
            "urgency":          bool(urgency_hits),
            "fear":             bool(fear_hits),
            "scarcity":         bool(scarcity_hits),
            "authority":        bool(authority_hits),
            "curiosity":        bool(curiosity_hits),
            "urgency_hits":     urgency_hits,
            "fear_hits":        fear_hits,
            "scarcity_hits":    scarcity_hits,
            "authority_hits":   authority_hits,
            "curiosity_hits":   curiosity_hits,
            "any_detected":     any([urgency_hits, fear_hits, scarcity_hits, authority_hits, curiosity_hits]),
        }

    # ── 3. Credential Harvesting Detection ───────────────────────────────────

    def _detect_credential_harvesting(self, text: str) -> Dict[str, Any]:
        """
        Identify explicit requests for credentials, PII, and sensitive secrets
        in the email body.
        """
        matched_types: List[str] = []
        for pattern, label in _CREDENTIAL_PATTERNS:
            if re.search(pattern, text, re.I) and label not in matched_types:
                matched_types.append(label)

        return {
            "detected":  bool(matched_types),
            "types":     matched_types,
            "count":     len(matched_types),
        }

    # ── 4. Brand Impersonation Detection ─────────────────────────────────────

    def _detect_brand_impersonation(
        self,
        text: str,
        links: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Detect known brand mentions in text and cross-check hyperlink domains
        for mismatches that indicate spoofing.
        """
        matched_brands: Set[str] = set()
        link_mismatch_brands: List[str] = []

        for brand, keywords in _BRANDS.items():
            for kw in keywords:
                if kw.lower() in text:
                    matched_brands.add(brand)
                    break

        # Cross-check: brand mentioned → links don't point to brand's official domain
        for brand in matched_brands:
            official_domain_fragments = [
                kw.lower().replace(" ", "").replace(".", "")
                for kw in _BRANDS[brand]
            ]
            for link in links:
                href = link.get("href", "")
                try:
                    parsed = urllib.parse.urlparse(href)
                    netloc = parsed.netloc.lower()
                    # A link exists that does NOT contain the brand's domain
                    if netloc and not any(frag in netloc.replace(".", "") for frag in official_domain_fragments):
                        if brand not in link_mismatch_brands:
                            link_mismatch_brands.append(brand)
                except Exception:
                    pass

        return {
            "detected":        bool(matched_brands),
            "matched_brands":  matched_brands,
            "link_mismatch":   bool(link_mismatch_brands),
            "mismatch_brands": link_mismatch_brands,
        }

    # ── 5. Hyperlink Analysis ─────────────────────────────────────────────────

    def _analyze_hyperlinks(
        self,
        links: List[Dict[str, str]],
        text: str,
    ) -> Dict[str, Any]:
        """
        Evaluate all embedded hyperlinks for:
        - IP-based URLs (no hostname)
        - URL shorteners
        - Display text vs. href domain mismatch
        - Suspicious TLD
        - Excessive link count (> 10)
        """
        suspicious_links: List[str] = []
        ip_links:         List[str] = []
        shortened_links:  List[str] = []

        for link in links:
            href = link.get("href", "")
            text_label = link.get("text", "")
            if not href:
                continue

            try:
                parsed    = urllib.parse.urlparse(href)
                netloc    = parsed.netloc.lower().split(":")[0]  # strip port
                host_only = netloc.lstrip("www.")
            except Exception:
                continue

            is_suspicious = False

            # ── Raw IP address ─────────────────────────────────────────────
            try:
                ipaddress.ip_address(netloc)
                ip_links.append(href)
                is_suspicious = True
            except ValueError:
                pass

            # ── URL shortener ──────────────────────────────────────────────
            if host_only in _URL_SHORTENERS:
                shortened_links.append(href)
                is_suspicious = True

            # ── Suspicious TLD ─────────────────────────────────────────────
            for tld in _SUSPICIOUS_TLDS:
                if host_only.endswith(tld):
                    is_suspicious = True
                    break

            # ── Display text ↔ href domain mismatch ────────────────────────
            if text_label and re.search(r"https?://", text_label, re.I):
                try:
                    label_host = urllib.parse.urlparse(text_label).netloc.lower()
                    if label_host and label_host != netloc:
                        is_suspicious = True
                except Exception:
                    pass

            # ── http:// in display text but href points elsewhere ───────────
            if text_label.lower().startswith("http") and netloc not in text_label.lower():
                is_suspicious = True

            if is_suspicious and href not in suspicious_links:
                suspicious_links.append(href)

        excessive = len(links) > 10

        return {
            "suspicious_count":  len(suspicious_links),
            "suspicious_links":  suspicious_links,
            "ip_links":          len(ip_links),
            "shortened_links":   len(shortened_links),
            "total_links":       len(links),
            "excessive_links":   excessive,
            "detected":          bool(suspicious_links) or excessive,
        }

    # ── 6. Attachment Lure Detection ──────────────────────────────────────────

    def _detect_attachment_lures(self, text: str) -> Dict[str, Any]:
        """
        Detect dangerous file extension references and document lure language
        in the email body.
        """
        matched_types: List[str] = []
        for pattern, label in _DANGEROUS_EXTENSIONS:
            if re.search(pattern, text, re.I) and label not in matched_types:
                matched_types.append(label)

        return {
            "detected": bool(matched_types),
            "types":    matched_types,
            "count":    len(matched_types),
        }

    # ── 7. Financial Request Detection ───────────────────────────────────────

    def _detect_financial_requests(self, text: str) -> Dict[str, Any]:
        """Identify payment, wire-transfer, and financial incentive language."""
        hits = [p for p in _FINANCIAL_PATTERNS if re.search(p, text, re.I)]
        return {
            "detected": bool(hits),
            "patterns": hits,
            "count":    len(hits),
        }

    # ── 8. QR Code Phishing Detection ────────────────────────────────────────

    def _detect_qr_references(self, text: str) -> Dict[str, Any]:
        """Detect QR code phishing references in email body."""
        hits = [p for p in _QR_PATTERNS if re.search(p, text, re.I)]
        return {
            "detected": bool(hits),
            "patterns": hits,
        }

    # =========================================================================
    # ── SCORING ENGINE ────────────────────────────────────────────────────────
    # =========================================================================

    def _calculate_risk_score(
        self,
        social_eng:  Dict[str, Any],
        credentials: Dict[str, Any],
        brands:      Dict[str, Any],
        hyperlinks:  Dict[str, Any],
        attachments: Dict[str, Any],
        financial:   Dict[str, Any],
        qr:          Dict[str, Any],
    ) -> Tuple[int, str, int]:
        """
        Aggregate weighted penalties into a 0–100 content risk score.

        Penalty Table
        -------------
        Urgency language        → +10
        Fear tactics            → +10
        Scarcity / curiosity    → +5 each
        Authority impersonation → +8
        Credential harvesting   → +25
        Brand impersonation     → +20   (link mismatch: +5 extra)
        Suspicious hyperlinks   → +15
        Attachment lure         → +15
        Financial request       → +20
        QR phishing             → +15
        Excessive links         → +5

        Returns
        -------
        (score: int, risk: str, confidence: int)
        """
        penalty = 0
        signals = 0

        if social_eng["urgency"]:
            penalty += 10;  signals += 1
        if social_eng["fear"]:
            penalty += 10;  signals += 1
        if social_eng["scarcity"]:
            penalty += 5;   signals += 1
        if social_eng["authority"]:
            penalty += 8;   signals += 1
        if social_eng["curiosity"]:
            penalty += 5;   signals += 1
        if credentials["detected"]:
            penalty += 25;  signals += 1
            # Additional penalty per extra credential type (max +10)
            extra = min((credentials["count"] - 1) * 3, 10)
            penalty += extra
        if brands["detected"]:
            penalty += 20;  signals += 1
            if brands["link_mismatch"]:
                penalty += 5
        if hyperlinks["detected"]:
            penalty += 15;  signals += 1
        if hyperlinks["excessive_links"]:
            penalty += 5
        if attachments["detected"]:
            penalty += 15;  signals += 1
        if financial["detected"]:
            penalty += 20;  signals += 1
        if qr["detected"]:
            penalty += 15;  signals += 1

        score = min(max(penalty, 0), 100)

        if score >= 80:
            risk = "CRITICAL"
        elif score >= 60:
            risk = "HIGH"
        elif score >= 30:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # Confidence: based on number of independent corroborating signals
        if signals >= 5:
            confidence = 98
        elif signals == 4:
            confidence = 92
        elif signals == 3:
            confidence = 85
        elif signals == 2:
            confidence = 72
        elif signals == 1:
            confidence = 55
        else:
            confidence = 30

        return score, risk, confidence

    # =========================================================================
    # ── FINDINGS & RECOMMENDATIONS ────────────────────────────────────────────
    # =========================================================================

    def _collect_findings(
        self,
        social_eng:       Dict[str, Any],
        credentials:      Dict[str, Any],
        brands:           Dict[str, Any],
        hyperlinks:       Dict[str, Any],
        attachments:      Dict[str, Any],
        financial:        Dict[str, Any],
        qr:               Dict[str, Any],
        findings:         List[str],
        recommendations:  List[str],
    ) -> None:
        """Populate findings and recommendations lists in-place."""

        # ── Findings ───────────────────────────────────────────────────────
        if social_eng["urgency"]:
            findings.append("Urgency language detected — message creates artificial time pressure.")
        if social_eng["fear"]:
            findings.append("Fear tactics detected — message references account suspension or security threats.")
        if social_eng["scarcity"]:
            findings.append("Scarcity tactics detected — message uses limited-time or exclusive-offer language.")
        if social_eng["authority"]:
            findings.append("Authority impersonation detected — message references IT, management, or compliance teams.")
        if social_eng["curiosity"]:
            findings.append("Curiosity bait detected — message uses prize or reward language.")

        if credentials["detected"]:
            types_str = ", ".join(credentials["types"])
            findings.append(
                f"Credential harvesting attempt identified — {credentials['count']} sensitive "
                f"data type(s) requested: {types_str}."
            )

        if brands["detected"]:
            brand_str = ", ".join(sorted(brands["matched_brands"]))
            findings.append(f"Brand mention(s) detected: {brand_str}.")
            if brands["link_mismatch"]:
                mismatch_str = ", ".join(brands["mismatch_brands"])
                findings.append(
                    f"Brand impersonation confirmed — {mismatch_str} referenced but "
                    "embedded hyperlinks point to unrelated domains."
                )

        if hyperlinks["ip_links"] > 0:
            findings.append(
                f"IP-based hyperlink(s) detected ({hyperlinks['ip_links']}) — "
                "legitimate senders rarely use raw IP addresses."
            )
        if hyperlinks["shortened_links"] > 0:
            findings.append(
                f"URL shortener(s) detected ({hyperlinks['shortened_links']}) — "
                "final destination is obscured from the recipient."
            )
        if hyperlinks["excessive_links"]:
            findings.append(
                f"Excessive number of hyperlinks ({hyperlinks['total_links']}) — "
                "typical phishing emails embed many redirect links."
            )
        if hyperlinks["suspicious_count"] > 0:
            findings.append(
                f"Suspicious hyperlink(s) found ({hyperlinks['suspicious_count']}) — "
                "links exhibit phishing indicators (IP host, suspicious TLD, or display text mismatch)."
            )

        if attachments["detected"]:
            types_str = ", ".join(attachments["types"])
            findings.append(
                f"Dangerous attachment lure identified — references to: {types_str}. "
                "These file types are commonly weaponised."
            )

        if financial["detected"]:
            findings.append(
                "Financial request detected — message solicits payment, wire transfer, "
                "or gift card transactions."
            )

        if qr["detected"]:
            findings.append(
                "QR code phishing reference detected — email instructs recipient to "
                "scan a QR code, potentially bypassing URL filters."
            )

        # ── Recommendations ────────────────────────────────────────────────
        if not findings:
            recommendations.append("No phishing indicators detected. Continue routine monitoring.")
            return

        recommendations.append("Quarantine the email and prevent delivery to the recipient's inbox.")
        recommendations.append("Block the sender address and sending domain at the email gateway.")
        recommendations.append("Warn the recipient — do not click links, open attachments, or reply.")

        if credentials["detected"]:
            recommendations.append(
                "If the recipient has already interacted, immediately reset all credentials "
                "and invalidate active sessions."
            )
        if brands["link_mismatch"]:
            recommendations.append(
                "Report brand impersonation to the affected organisation's abuse / phishing team."
            )
        if hyperlinks["suspicious_count"] > 0 or hyperlinks["shortened_links"] > 0:
            recommendations.append(
                "Expand and analyse all embedded URLs — submit to threat intelligence platforms "
                "(e.g., VirusTotal, URLhaus)."
            )
        if attachments["detected"]:
            recommendations.append(
                "Scan any referenced attachments in an isolated sandbox environment "
                "before allowing any access."
            )
        if financial["detected"]:
            recommendations.append(
                "Alert the finance team — do not authorise any payment, wire transfer, "
                "or gift card purchase without out-of-band verification."
            )
        if qr["detected"]:
            recommendations.append(
                "Extract and inspect the QR code URL using a safe QR decoder — "
                "do not scan with a personal device."
            )
        recommendations.append(
            "Submit extracted indicators of compromise (IoCs) to threat intelligence feeds."
        )

    # =========================================================================
    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    # =========================================================================

    def _generate_executive_summary(
        self,
        score:      int,
        risk:       str,
        social_eng: Dict[str, Any],
        credentials: Dict[str, Any],
        brands:     Dict[str, Any],
        hyperlinks: Dict[str, Any],
        attachments: Dict[str, Any],
        financial:  Dict[str, Any],
        qr:         Dict[str, Any],
    ) -> str:
        """Generate a concise, enterprise-grade executive summary."""

        if score == 0:
            return (
                "Content analysis identified no phishing indicators in the email. "
                "The message does not exhibit social engineering, credential harvesting, "
                "brand impersonation, or suspicious hyperlink characteristics at this time."
            )

        indicators: List[str] = []
        if social_eng["urgency"] or social_eng["fear"]:
            indicators.append("social engineering tactics (urgency/fear language)")
        if social_eng["scarcity"]:
            indicators.append("scarcity and artificial time-pressure language")
        if social_eng["authority"]:
            indicators.append("authority impersonation")
        if credentials["detected"]:
            indicators.append(
                f"credential harvesting ({credentials['count']} sensitive data type(s) solicited)"
            )
        if brands["detected"] and brands["link_mismatch"]:
            brand_str = ", ".join(sorted(brands["matched_brands"]))
            indicators.append(f"{brand_str} brand impersonation with mismatched hyperlinks")
        elif brands["detected"]:
            brand_str = ", ".join(sorted(brands["matched_brands"]))
            indicators.append(f"{brand_str} brand reference(s)")
        if hyperlinks["suspicious_count"] > 0:
            indicators.append(
                f"{hyperlinks['suspicious_count']} suspicious hyperlink(s) "
                "(IP-based, shortened, or suspicious TLD)"
            )
        if attachments["detected"]:
            indicators.append("dangerous attachment lure(s)")
        if financial["detected"]:
            indicators.append("financial or payment request")
        if qr["detected"]:
            indicators.append("QR code phishing reference")

        indicators_str = "; ".join(indicators) if indicators else "multiple phishing characteristics"

        verdict = {
            "CRITICAL": (
                f"HIGH-CONFIDENCE PHISHING — Content risk score: {score}/100 (CRITICAL). "
                f"This email exhibits {len(indicators)} independent phishing indicator(s): "
                f"{indicators_str}. The message should be treated as malicious and handled "
                "immediately. Quarantine, block, and initiate incident response."
            ),
            "HIGH": (
                f"Content analysis identified a HIGH-risk phishing attempt "
                f"(score: {score}/100). "
                f"The following indicators were detected: {indicators_str}. "
                "The email should be quarantined and the sender blocked pending investigation."
            ),
            "MEDIUM": (
                f"Content analysis identified MEDIUM-risk phishing characteristics "
                f"(score: {score}/100). "
                f"Indicators include: {indicators_str}. "
                "Exercise caution — treat this email as potentially malicious until further review."
            ),
            "LOW": (
                f"Content analysis identified LOW-risk phishing indicators "
                f"(score: {score}/100): {indicators_str}. "
                "No immediate action required, but continue monitoring for escalation."
            ),
        }

        return verdict.get(risk, f"Content risk score: {score}/100 ({risk}). Indicators: {indicators_str}.")
