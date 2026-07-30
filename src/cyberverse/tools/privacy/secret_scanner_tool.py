import os
import re
import json
import math
import logging
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from crewai.tools import BaseTool

# Optional library imports with fallbacks
try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False

try:
    import docx  # python-docx
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    import detect_secrets
    HAS_DETECT_SECRETS = True
except ImportError:
    HAS_DETECT_SECRETS = False

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class SecretScannerToolInput(BaseModel):
    """Input schema for SecretScannerTool."""
    file_path: Optional[str] = Field(None, description="Absolute path to a file (.env, .json, .yaml, .txt, .pdf, .docx, .log) to scan for secrets.")
    text: Optional[str] = Field(None, description="Direct raw text string to scan for secrets and sensitive keys.")


class SecretScannerTool(BaseTool):
    name: str = "Secret Scanner Tool"
    description: str = (
        "Scans text strings, code, environment variables (.env), configuration files, and documents "
        "for exposed sensitive credentials, API keys, private keys, database connection strings, "
        "and high-entropy tokens across Cloud, AI providers, Git platforms, Messaging services, and Auth systems."
    )
    args_schema: Type[BaseModel] = SecretScannerToolInput

    def _run(self, file_path: Optional[str] = None, text: Optional[str] = None) -> str:
        """Execute secret scanning on file path or raw text string."""
        warnings: List[str] = []

        # 1. Resolve text input
        lines, target_name = self._resolve_text_lines(file_path, text, warnings)

        if not lines:
            return json.dumps({
                "success": False,
                "findings": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "risk_score": 0,
                "error": "No readable text content or file provided for secret scanning."
            }, indent=2)

        try:
            # 2. Scan lines for patterns and high entropy tokens
            findings = self._scan_lines_for_secrets(lines, warnings)

            # 3. Calculate summary metrics and risk score
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for item in findings:
                sev = item["severity"].lower()
                summary[sev] = summary.get(sev, 0) + 1

            risk_score = self._calculate_risk_score(summary)

            return json.dumps({
                "success": True,
                "findings": findings,
                "summary": summary,
                "risk_score": risk_score,
                "error": None
            }, indent=2)

        except Exception as e:
            logger.error(f"Error executing SecretScannerTool: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "findings": [],
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "risk_score": 0,
                "error": f"Secret scanning error: {str(e)}"
            }, indent=2)

    def _resolve_text_lines(self, file_path: Optional[str], text: Optional[str], warnings: List[str]) -> tuple[List[str], str]:
        """Extract lines of text from direct text input or file path."""
        if text and text.strip():
            return text.splitlines(), "Direct Text Input"

        if file_path and isinstance(file_path, str):
            clean_path = os.path.abspath(file_path.strip().strip('"').strip("'"))
            if not os.path.exists(clean_path):
                warnings.append(f"File not found at path: {clean_path}")
                return [], clean_path

            ext = os.path.splitext(clean_path)[1].lower()
            filename = os.path.basename(clean_path)

            # 1. Standard text / env / json / log files
            text_exts = {".txt", ".env", ".local", ".production", ".json", ".yaml", ".yml", ".log", ".csv", ".md", ".xml", ".ini", ".conf"}
            if ext in text_exts or filename.startswith(".env"):
                try:
                    with open(clean_path, "r", encoding="utf-8", errors="ignore") as f:
                        return f.read().splitlines(), filename
                except Exception as e:
                    warnings.append(f"File read error: {str(e)}")

            # 2. PDF files
            elif ext == ".pdf" and HAS_FITZ:
                try:
                    doc = fitz.open(clean_path)
                    pdf_text = ""
                    for page in doc:
                        pdf_text += page.get_text() + "\n"
                    return pdf_text.splitlines(), filename
                except Exception as fitz_err:
                    warnings.append(f"PDF text extraction warning: {str(fitz_err)}")

            # 3. DOCX files
            elif ext == ".docx" and HAS_DOCX:
                try:
                    doc = docx.Document(clean_path)
                    paragraphs = [p.text for p in doc.paragraphs if p.text]
                    return paragraphs, filename
                except Exception as docx_err:
                    warnings.append(f"DOCX text extraction warning: {str(docx_err)}")

            # Generic fallback read
            try:
                with open(clean_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read().splitlines(), filename
            except Exception:
                pass

        return [], "Unknown Source"

    def _scan_lines_for_secrets(self, lines: List[str], warnings: List[str]) -> List[Dict[str, Any]]:
        """Scan each line for regex pattern matches and Shannon entropy tokens."""
        findings: List[Dict[str, Any]] = []
        seen_keys = set()

        # Secret Regex Pattern Library
        pattern_library = [
            # --- Cloud Credentials ---
            ("AWS_ACCESS_KEY_ID", r'\b(AKIA[0-9A-Z]{16})\b', "CRITICAL", 0.99, "Rotate AWS access key immediately in IAM console."),
            ("AWS_SECRET_ACCESS_KEY", r'(?i)\baws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?\b', "CRITICAL", 0.98, "Revoke and rotate AWS Secret Access Key in AWS IAM."),
            ("AWS_SESSION_TOKEN", r'(?i)\baws_session_token\s*[:=]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?\b', "HIGH", 0.95, "Purge temporary AWS Session Token."),
            ("AZURE_STORAGE_KEY", r'(?i)\bAccountKey=([a-zA-Z0-9+/=]{86,88})\b', "CRITICAL", 0.98, "Regenerate Azure Storage Account Access Keys."),
            ("AZURE_CONNECTION_STRING", r'(?i)\bDefaultEndpointsProtocol=https;AccountName=[^;\s]+;AccountKey=[^;\s]+\b', "CRITICAL", 0.98, "Rotate Azure Storage Connection String."),
            ("AZURE_SAS_TOKEN", r'\bsig=([a-zA-Z0-9%2F%2B%3D]{43,88})\b', "HIGH", 0.95, "Revoke Azure SAS Token."),
            ("GOOGLE_API_KEY", r'\b(AIzaSy[0-9A-Za-z_-]{33})\b', "HIGH", 0.98, "Restrict and rotate Google API Key in GCP Console."),
            ("GOOGLE_OAUTH_CLIENT_ID", r'\b([0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b', "MEDIUM", 0.90, "Inspect Google OAuth Client ID scope."),
            ("GOOGLE_SERVICE_ACCOUNT_JSON", r'"type":\s*"service_account"', "CRITICAL", 0.99, "Revoke Google Service Account key in GCP."),
            ("FIREBASE_API_KEY", r'(?i)\bfirebase[a-z_]*key\s*[:=]\s*["\']?([a-zA-Z0-9_-]{39})["\']?\b', "HIGH", 0.95, "Rotate Firebase API Key."),

            # --- AI Provider Keys ---
            ("OPENAI_API_KEY", r'\b(sk-(?:proj-|admin-|svcacct-)?[a-zA-Z0-9_-]{20,})\b', "CRITICAL", 0.99, "Revoke OpenAI API Key immediately in OpenAI Dashboard."),
            ("GEMINI_API_KEY", r'(?i)\bgemini[a-z_]*key\s*[:=]\s*["\']?(AIzaSy[0-9A-Za-z_-]{33})["\']?\b', "CRITICAL", 0.98, "Rotate Gemini API Key in Google AI Studio."),
            ("ANTHROPIC_API_KEY", r'\b(sk-ant-api[0-9a-zA-Z_-]{20,})\b', "CRITICAL", 0.99, "Revoke Anthropic API Key in Console."),
            ("HUGGINGFACE_TOKEN", r'\b(hf_[a-zA-Z0-9]{32,})\b', "HIGH", 0.98, "Revoke Hugging Face Access Token."),
            ("COHERE_API_KEY", r'(?i)\bcohere[a-z_]*key\s*[:=]\s*["\']?([a-zA-Z0-9]{40})["\']?\b', "HIGH", 0.95, "Rotate Cohere API Key."),

            # --- Git Platforms ---
            ("GITHUB_PAT", r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})\b', "CRITICAL", 0.99, "Revoke GitHub Personal Access Token immediately."),
            ("GITLAB_TOKEN", r'\b(glpat-[a-zA-Z0-9_-]{20,})\b', "CRITICAL", 0.99, "Revoke GitLab Personal Access Token."),
            ("BITBUCKET_TOKEN", r'(?i)\bbitbucket[a-z_]*token\s*[:=]\s*["\']?([a-zA-Z0-9]{32,})["\']?\b', "HIGH", 0.95, "Revoke Bitbucket App Password / Token."),

            # --- Messaging ---
            ("SLACK_TOKEN", r'\b(xox[baprs]-[0-9a-zA-Z]{10,})\b', "CRITICAL", 0.99, "Revoke Slack API Token in Slack App Settings."),
            ("DISCORD_BOT_TOKEN", r'\b([MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38})\b', "CRITICAL", 0.98, "Regenerate Discord Bot Token."),
            ("TELEGRAM_BOT_TOKEN", r'\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b', "CRITICAL", 0.98, "Revoke Telegram Bot Token via BotFather."),

            # --- Authentication ---
            ("JWT_TOKEN", r'\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b', "HIGH", 0.95, "Purge hardcoded JWT token; set short expiry."),
            ("OAUTH_BEARER_TOKEN", r'(?i)\bbearer\s+([a-zA-Z0-9_\-\.=]{20,})\b', "HIGH", 0.90, "Rotate OAuth Bearer Token."),
            ("BASIC_AUTH_HEADER", r'(?i)\bauthorization:\s*basic\s+([a-zA-Z0-9+/=]{10,})\b', "MEDIUM", 0.90, "Remove hardcoded Basic Auth credentials."),

            # --- Database Connection Strings ---
            ("MONGODB_URI", r'\b(mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^\s]+)\b', "CRITICAL", 0.99, "Rotate database credentials and move connection string to secrets manager."),
            ("POSTGRESQL_URI", r'\b(postgresql://[^:\s]+:[^@\s]+@[^\s]+)\b', "CRITICAL", 0.99, "Rotate PostgreSQL password."),
            ("MYSQL_URI", r'\b(mysql://[^:\s]+:[^@\s]+@[^\s]+)\b', "CRITICAL", 0.99, "Rotate MySQL database password."),
            ("REDIS_URI", r'\b(redis://:[^@\s]+@[^\s]+)\b', "HIGH", 0.95, "Rotate Redis auth password."),

            # --- Private Keys & Certificates ---
            ("RSA_PRIVATE_KEY", r'(-----BEGIN RSA PRIVATE KEY-----)', "CRITICAL", 0.99, "EMERGENCY: RSA Private Key exposed! Revoke and replace certificate/key pair."),
            ("SSH_PRIVATE_KEY", r'(-----BEGIN OPENSSH PRIVATE KEY-----)', "CRITICAL", 0.99, "EMERGENCY: SSH Private Key exposed! Delete key from authorized_keys and re-key."),
            ("PGP_PRIVATE_KEY", r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)', "CRITICAL", 0.99, "EMERGENCY: PGP Private Key exposed! Revoke key on public keyservers."),
            ("PEM_CERTIFICATE", r'(-----BEGIN CERTIFICATE-----)', "LOW", 0.85, "Inspect public X.509 certificate metadata.")
        ]

        for line_num, line_str in enumerate(lines, start=1):
            stripped_line = line_str.strip()
            if not stripped_line:
                continue

            # 1. Pattern Matching
            for stype, regex_pat, sev, conf, rec in pattern_library:
                for match in re.finditer(regex_pat, line_str):
                    matched_val = match.group(1) if match.groups() else match.group(0)
                    key = (stype, line_num, matched_val)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append({
                            "type": stype,
                            "severity": sev,
                            "value_preview": self._mask_secret(matched_val),
                            "line": line_num,
                            "confidence": conf,
                            "recommendation": rec
                        })

            # 2. Shannon Entropy Scanner for unknown high-entropy strings
            words = re.findall(r'[a-zA-Z0-9_+/=-]{16,}', stripped_line)
            for word in words:
                # Ignore common words or standard hex/base64 strings already matched
                if any(w in word for w in ["BEGIN", "END", "http", "mongodb", "postgresql"]):
                    continue

                entropy = self._calculate_entropy(word)
                if entropy > 4.5:
                    key = ("HIGH_ENTROPY_SECRET", line_num, word)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append({
                            "type": "HIGH_ENTROPY_SECRET",
                            "severity": "HIGH",
                            "value_preview": self._mask_secret(word),
                            "line": line_num,
                            "confidence": round(min(0.95, 0.70 + (entropy - 4.5) * 0.15), 2),
                            "recommendation": "Inspect high-entropy random string for potential unformatted secret or password."
                        })

        return findings

    def _mask_secret(self, val: str) -> str:
        """Mask secret values except first 4 and last 4 characters."""
        val_clean = val.strip()
        length = len(val_clean)
        if length <= 8:
            return val_clean[0:2] + "..." + val_clean[-2:] if length > 4 else "..."
        return f"{val_clean[:4]}...{val_clean[-4:]}"

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon Entropy (bits per character) of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log2(p) for p in prob if p > 0])

    def _calculate_risk_score(self, summary: Dict[str, int]) -> int:
        """Calculate overall risk score from 0 to 100 based on severity findings."""
        score = (
            summary.get("critical", 0) * 30 +
            summary.get("high", 0) * 20 +
            summary.get("medium", 0) * 10 +
            summary.get("low", 0) * 5
        )
        return min(100, score)
