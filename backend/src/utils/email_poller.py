import os
import logging
import threading
from imap_tools import MailBox, AND
from src.phishing_detection_agent.flow_runner import run_phishing_flow

logger = logging.getLogger(__name__)

def idle_loop():
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    imap_host = os.getenv("IMAP_HOST", "imap.gmail.com")
    
    if not email_user or not email_pass:
        logger.warning("Email poller is disabled because EMAIL_USER or EMAIL_PASS is not set.")
        return

    logger.info(f"Connecting to IMAP server {imap_host} to wait for new emails (IDLE mode)...")
    
    while True:
        try:
            with MailBox(imap_host).login(email_user, email_pass, initial_folder='INBOX') as mailbox:
                while True:
                    # Fetch any currently unseen messages first
                    messages = list(mailbox.fetch(AND(seen=False), mark_seen=True))
                    
                    for msg in messages:
                        subject = msg.subject
                        body = msg.text or msg.html
                        logger.info(f"Analyzing new email: {subject}")
                        
                        analysis_text = f"Subject: {subject}\n\nBody: {body}"
                        
                        try:
                            report = run_phishing_flow(
                                url_or_text=analysis_text, 
                                system_prompt="Analyze this newly received email for phishing attempts."
                            )
                            logger.info(f"Phishing analysis complete. Status: {report.get('status')}, Risk Level: {report.get('risk_level')}")
                        except Exception as e:
                            logger.error(f"Failed to analyze email '{subject}': {e}")
                    
                    # Enter IDLE mode and wait for the server to notify us of new emails
                    # This blocks until a change happens in the INBOX (like a new email)
                    responses = mailbox.idle.wait(timeout=60 * 5)
                    
                    # If we got a response (e.g. 'EXISTS'), the loop continues and fetches the new unseen emails.
        except Exception as e:
            logger.error(f"Error in IMAP IDLE connection: {e}. Reconnecting in 10 seconds...")
            import time
            time.sleep(10)

def start_email_poller():
    """
    Initializes and starts the IMAP IDLE background listener thread.
    """
    t = threading.Thread(target=idle_loop, daemon=True)
    t.start()
    logger.info("Started Background Email IDLE Listener.")
