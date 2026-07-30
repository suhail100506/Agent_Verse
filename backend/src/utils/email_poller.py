import os
import logging
try:
    from imap_tools import MailBox, AND
    from apscheduler.schedulers.background import BackgroundScheduler
    HAS_IMAP = True
except ImportError:
    HAS_IMAP = False
from src.phishing_detection_agent.flow_runner import run_phishing_flow

logger = logging.getLogger(__name__)

def check_new_emails_and_analyze():
    """
    Connects to the IMAP server, fetches new (unseen) emails,
    analyzes them for phishing, and marks them as read.
    """
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    imap_host = os.getenv("IMAP_HOST", "imap.gmail.com")
    
    if not email_user or not email_pass:
        logger.warning("Email poller is disabled because EMAIL_USER or EMAIL_PASS is not set.")
        return

    logger.info(f"Connecting to IMAP server {imap_host} to check for new emails...")
    try:
        # Connect and login
        with MailBox(imap_host).login(email_user, email_pass, initial_folder='INBOX') as mailbox:
            # Fetch all UNSEEN messages. By default, imap-tools marks them as SEEN (read)
            # so they won't be fetched again next time.
            messages = list(mailbox.fetch(AND(seen=False)))
            
            if not messages:
                logger.info("No new emails found.")
                return
                
            logger.info(f"Found {len(messages)} new email(s). Processing...")
            
            for msg in messages:
                subject = msg.subject
                body = msg.text or msg.html
                
                logger.info(f"Analyzing email: {subject}")
                
                # Combine subject and body for analysis
                analysis_text = f"Subject: {subject}\n\nBody: {body}"
                
                # Run the phishing flow
                try:
                    # Provide an empty credential_id or a specific one if needed
                    report = run_phishing_flow(
                        url_or_text=analysis_text, 
                        system_prompt="Analyze this newly received email for phishing attempts."
                    )
                    logger.info(f"Phishing analysis complete. Status: {report.get('status')}, Risk Level: {report.get('risk_level')}")
                except Exception as e:
                    logger.error(f"Failed to analyze email '{subject}': {e}")
                    
    except Exception as e:
        logger.error(f"Error checking emails: {e}")

def start_email_poller():
    """
    Initializes and starts the APScheduler background job.
    """
    if not HAS_IMAP:
        logger.info("IMAP polling dependencies not installed; skipping email poller.")
        return
    scheduler = BackgroundScheduler()
    # Run the poller every 3 minutes (can be adjusted)
    scheduler.add_job(check_new_emails_and_analyze, 'interval', minutes=3)
    scheduler.start()
    logger.info("Started Background Email Poller (Checking every 3 minutes).")
