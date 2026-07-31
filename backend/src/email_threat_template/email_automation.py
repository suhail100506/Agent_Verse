import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.utils.mongo_client import get_mongo_collection

logger = logging.getLogger(__name__)

def send_alert_email_if_needed(
    investigation_id: str,
    phishing_risk_score: int,
    malware_detected: bool,
    recipient_email: str,
    incident_severity: str = "Unknown",
    threat_level: str = "Unknown",
    recommended_action: str = "Unknown"
) -> bool:
    """
    Evaluates if an alert email should be sent, deduplicates via MongoDB,
    and sends the email if required.
    """
    # 1. Rule Evaluation
    if phishing_risk_score <= 70 and not malware_detected:
        logger.info(f"[{investigation_id}] No alert required (Phishing Score: {phishing_risk_score}, Malware: {malware_detected}).")
        return False

    # 2. Duplicate Prevention via MongoDB
    collection = get_mongo_collection("email_threat_alerts")
    if collection is not None:
        existing = collection.find_one({"investigation_id": investigation_id, "email_sent": True})
        if existing:
            logger.info(f"[{investigation_id}] Alert already sent. Skipping duplicate.")
            return False
    else:
        logger.warning(f"[{investigation_id}] MongoDB not available, proceeding without deduplication check.")

    # 3. SMTP Configuration
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_email = os.getenv("SMTP_EMAIL")
    smtp_password = os.getenv("SMTP_PASSWORD")
    soc_admin_email = os.getenv("SOC_ADMIN_EMAIL", "soc-admin@cyberverse.ai")

    if not smtp_email or not smtp_password:
        logger.error(f"[{investigation_id}] SMTP credentials missing in .env. Cannot send alert.")
        return False

    target_email = recipient_email if recipient_email else soc_admin_email

    # 4. Email Content Construction
    msg = MIMEMultipart()
    msg['From'] = smtp_email
    msg['To'] = target_email
    msg['Subject'] = "🚨 Cyberverse Security Alert – Suspicious Email Detected"

    body = f"""Hello,

Our Cyberverse AI Security Platform has detected a potentially malicious email.

Investigation Summary:
- Risk Score: {phishing_risk_score}
- Threat Level: {threat_level}
- Malware Status: {"Detected" if malware_detected else "Clean"}
- Incident Severity: {incident_severity}
- Recommended Action: {recommended_action}

Please avoid opening attachments or clicking links until this email has been verified.

Thank you,
Cyberverse AI Security Platform
"""
    msg.attach(MIMEText(body, 'plain'))

    # 5. Send Email
    try:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_email, smtp_password)
        server.send_message(msg)
        server.quit()
        logger.info(f"[{investigation_id}] Alert email successfully sent to {target_email}.")
        
        # 6. Log to MongoDB
        if collection is not None:
            collection.update_one(
                {"investigation_id": investigation_id},
                {"$set": {"investigation_id": investigation_id, "email_sent": True}},
                upsert=True
            )
        return True
        
    except Exception as e:
        logger.error(f"[{investigation_id}] Failed to send alert email: {e}")
        return False
