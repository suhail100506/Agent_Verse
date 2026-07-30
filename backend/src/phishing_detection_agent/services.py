import re
from typing import List, Dict, Any, Tuple

# Simple heuristic lists
URGENT_KEYWORDS = ["urgent", "immediate action", "verify now", "account suspended", "security alert", "password expired", "action required"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".info", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq"]
KNOWN_DOMAINS = ["microsoft.com", "paypal.com", "amazon.com", "apple.com", "google.com"]

def analyze_sender(sender: str) -> Tuple[int, List[str]]:
    score = 0
    findings = []
    
    sender_lower = sender.lower()
    
    # Check for typo-squatting
    domain = sender_lower.split("@")[-1] if "@" in sender_lower else ""
    
    # Very basic typo-squatting detection
    for known in KNOWN_DOMAINS:
        if domain != known and known.replace("o", "0") in domain or known.replace("l", "I") in domain:
            score += 30
            findings.append(f"Typo-squatting detected in domain: {domain}")
            break
        elif domain != known and known.split(".")[0] in domain and not domain.endswith(known):
            # e.g., microsoft-support.com
            score += 30
            findings.append(f"Fake/Spoofed domain detected: {domain}")
            break
            
    # Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            findings.append(f"Suspicious TLD used: {tld}")
            break
            
    return score, findings

def analyze_subject(subject: str) -> Tuple[int, List[str]]:
    score = 0
    findings = []
    subject_lower = subject.lower()
    
    for kw in URGENT_KEYWORDS:
        if kw in subject_lower:
            score += 20
            findings.append(f"Urgent language detected in subject: '{kw}'")
            break
            
    return score, findings

def analyze_urls(urls: List[str]) -> Tuple[int, List[str]]:
    score = 0
    findings = []
    
    for url in urls:
        url_lower = url.lower()
        
        if url_lower.startswith("http://"):
            score += 10
            findings.append("HTTP (insecure) link found")
            
        # Check IP based URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
            score += 20
            findings.append("IP-based URL detected")
            
        # Shorteners
        if any(shortener in url_lower for shortener in ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]):
            score += 10
            findings.append("URL shortener used")
            
        # Typosquatting in URL
        for known in KNOWN_DOMAINS:
            if known.split(".")[0] in url_lower and known not in url_lower:
                score += 20
                findings.append(f"Suspicious URL resembling {known} detected")
                break
                
    # Cap URL score
    return min(score, 30), list(set(findings))

def analyze_headers(headers: str) -> Tuple[int, List[str]]:
    if not headers:
        return 0, []
        
    score = 0
    findings = []
    headers_lower = headers.lower()
    
    if "spf=fail" in headers_lower or "spf=softfail" in headers_lower:
        score += 15
        findings.append("SPF validation failed")
        
    if "dkim=fail" in headers_lower:
        score += 15
        findings.append("DKIM signature invalid")
        
    if "dmarc=fail" in headers_lower:
        score += 15
        findings.append("DMARC policy failed")
        
    return min(score, 15), findings

def calculate_overall_risk(
    sender_score: int, 
    subject_score: int, 
    url_score: int, 
    header_score: int, 
    ai_score: int
) -> Tuple[int, str]:
    # Weights max to ~100
    total_score = sender_score + subject_score + url_score + header_score + ai_score
    total_score = min(total_score, 100)
    
    if total_score <= 30:
        return total_score, "Safe"
    elif total_score <= 60:
        return total_score, "Medium"
    elif total_score <= 80:
        return total_score, "High"
    else:
        return total_score, "Critical"

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_alert_email(to_email: str, risk_level: str, findings: List[str]) -> Tuple[bool, str]:
    smtp_user = os.getenv("EMAIL_USER")
    smtp_pass = os.getenv("EMAIL_PASS")
    
    if not smtp_user or not smtp_pass:
        return False, "SMTP credentials not configured in .env"
        
    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = to_email
        
        # Add emojis based on risk level
        alert_emoji = "🚨" if risk_level in ["Critical", "High"] else "⚠️"
        msg["Subject"] = f"{alert_emoji} SECURITY ALERT: {risk_level} Risk Phishing Email Detected {alert_emoji}"
        
        body = f"""
Hello, 👋

Our security system has analyzed an email you recently received and flagged it as SUSPICIOUS.

🛑 Risk Level: {risk_level}

🔍 Findings:
"""
        for f in findings:
            body += f" ❌ {f}\n"
            
        body += "\n⚠️ Please DO NOT click any links, DO NOT download attachments, and DO NOT reply to this email.\n\nStay safe! 🛡️\nCyberverse Security Team"
        
        msg.attach(MIMEText(body, "plain"))
        
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        
        return True, ""
    except Exception as e:
        return False, str(e)

