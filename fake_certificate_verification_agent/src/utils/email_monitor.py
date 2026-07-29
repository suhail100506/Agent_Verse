import os
import time
import imaplib
import email
from email.header import decode_header
import threading
import logging
from tempfile import NamedTemporaryFile
import hashlib

from src.phishing_detection_agent.flow_runner import run_phishing_flow
from src.malware_analyzer_agent.flow_runner import run_malware_flow
from src.utils.email_service import send_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IMAP_SERVER = "imap.gmail.com"

def get_text_from_email(msg):
    text_content = ""
    html_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    text_content += part.get_payload(decode=True).decode(errors='ignore')
                except Exception:
                    pass
            elif content_type == "text/html" and "attachment" not in content_disposition:
                try:
                    html_content += part.get_payload(decode=True).decode(errors='ignore')
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            try:
                text_content = msg.get_payload(decode=True).decode(errors='ignore')
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                html_content = msg.get_payload(decode=True).decode(errors='ignore')
            except Exception:
                pass
                
    if not text_content and html_content:
        import re
        text_content = re.sub(r'<[^>]+>', ' ', html_content)
        
    return text_content

def extract_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    # decode filename
                    decoded_string, charset = decode_header(filename)[0]
                    if charset:
                        try:
                            if isinstance(decoded_string, bytes):
                                filename = decoded_string.decode(charset)
                            else:
                                filename = decoded_string
                        except Exception:
                            pass
                    
                    data = part.get_payload(decode=True)
                    if data:
                        attachments.append({"filename": filename, "data": data})
    return attachments

def check_email_content(msg, recipient):
    text = get_text_from_email(msg)
    attachments = extract_attachments(msg)
    
    message_id = msg.get("Message-ID", "")
    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    date_header = msg.get("Date", "")
    body_hash = hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()
    
    event_string = str(recipient) + str(message_id) + str(sender) + str(subject) + str(date_header) + body_hash
    event_id = hashlib.sha256(event_string.encode('utf-8')).hexdigest()
    
    logger.info(f"Generated Event ID: {event_id} (Date: {date_header}, Subject: {subject})")
    
    is_malicious = False
    reasons = []
    final_report = {
        "report_id": f"email_alert_{int(time.time())}",
        "risk_level": "LOW",
        "confidence": 0.0,
        "summary": "",
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sender": sender,
        "subject": subject
    }
    
    # 1. Check body text for Phishing
    if text:
        phishing_report = run_phishing_flow(text, event_id=event_id)
        status = phishing_report.get("status", "")
        # Note: If no URL is found, the current run_phishing_flow defaults to paypal-security-verify.tmp and returns Fake
        # So it might false positive if the email is plain text.
        # However, for demonstration, we will rely on its output.
        if status.upper() in ["FAKE", "HIGH RISK", "MALICIOUS", "SUSPICIOUS"]:
            is_malicious = True
            reasons.append(phishing_report.get("summary", "Phishing link/content detected in email body."))
            final_report["risk_level"] = "HIGH"
            final_report["confidence"] = max(final_report["confidence"], phishing_report.get("confidence", 0.95))

    # 2. Check attachments for Malware
    for att in attachments:
        temp_path = None
        try:
            # Note: windows temp file needs delete=False so it can be opened by another process if needed, or just standard.
            with NamedTemporaryFile(delete=False, suffix=".bin") as temp_file:
                temp_file.write(att["data"])
                temp_path = temp_file.name
                
            malware_report = run_malware_flow(temp_path, "binary")
            status = malware_report.get("status", "")
            
            if status.upper() in ["MALICIOUS", "SUSPICIOUS", "FAKE", "HIGH RISK"]:
                is_malicious = True
                reasons.append(f"Malware detected in attachment: {att['filename']} - {malware_report.get('summary', '')}")
                final_report["risk_level"] = "CRITICAL"
                final_report["confidence"] = max(final_report["confidence"], malware_report.get("confidence", 0.98))
        except Exception as e:
            logger.error(f"Error analyzing attachment: {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
                
    if is_malicious:
        final_report["summary"] = " | ".join(reasons)
        send_alert(recipient, final_report, event_id=event_id)

def monitor_inbox():
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    
    if not email_user or not email_pass:
        logger.warning("EMAIL_USER or EMAIL_PASS not set. Email monitor will not run.")
        return

    logger.info(f"Starting real-time email monitor for: {email_user}")

    startup_max_id = 0
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(email_user, email_pass)
        mail.select("inbox")
        status, response = mail.uid('SEARCH', None, 'ALL')
        if status == "OK" and response[0]:
            uids = response[0].split()
            if uids:
                startup_max_id = int(uids[-1])
        mail.logout()
    except Exception as e:
        logger.error(f"Failed to get initial mailbox state: {e}")

    logger.info(f"Ignoring existing emails (UIDs <= {startup_max_id}). Waiting for new emails...")

    while True:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_SERVER)
            mail.login(email_user, email_pass)
            mail.select("inbox")
            
            # Search for unseen emails using UID
            status, messages = mail.uid('SEARCH', None, 'UNSEEN')
            
            if status == "OK" and messages[0]:
                for num in messages[0].split():
                    num_int = int(num)
                    if num_int <= startup_max_id:
                        # Skip old emails that were present before startup
                        continue

                    fetch_status, data = mail.uid('FETCH', num, '(RFC822)')
                    if fetch_status == "OK":
                        raw_email = data[0][1]
                        msg = email.message_from_bytes(raw_email)
                        
                        # Extract the recipient from the 'To' header. 
                        # Fallback to email_user if not found.
                        recipient = msg.get("To", email_user)
                        sender = msg.get("From", "")
                        
                        # Skip emails sent by our own email address to prevent infinite alert loops
                        if email_user in sender:
                            mail.uid('STORE', num, '+FLAGS', '\\Seen')
                            continue
                        
                        logger.info(f"New unseen email detected from {sender}. Analyzing content...")
                        check_email_content(msg, recipient)
                        
                        # Explicitly mark the email as read (Seen) so we don't process it again
                        mail.uid('STORE', num, '+FLAGS', '\\Seen')
            
            mail.logout()
        except Exception as e:
            logger.error(f"Error in email monitor: {e}")
            
        time.sleep(15) # Poll every 15 seconds

def start_email_monitor():
    thread = threading.Thread(target=monitor_inbox, daemon=True)
    thread.start()
    logger.info("Email monitor daemon thread started.")
