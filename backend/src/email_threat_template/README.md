# Email Threat Investigation Template

This module provides the backend orchestration service for the **Email Threat Investigation** template.

## Overview
This workflow seamlessly chains three existing standalone agents:
1. **Phishing Detection Agent**
2. **Malware Analysis Agent**
3. **Incident Response Agent**

It analyzes emails, extracts attachments (from `.eml` and `.msg`), detects malicious payloads, formulates an automated incident response plan, and conditionally triggers email alerts using a deduplicated MongoDB record.

## Architecture

- **`main.py`**: The FastAPI orchestrator. Exposes `POST /api/template/email-threat-investigation`.
- **`email_automation.py`**: The alerting module. Reads SMTP configurations from `.env`, checks MongoDB to prevent duplicate alerts for the same `investigation_id`, and sends security alerts to the specified SOC admin or user.

## Dependencies & Setup

Ensure the following environment variables are configured in your `.env` file:
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SOC_ADMIN_EMAIL=admin@cyberverse.ai
MONGODB_URI=mongodb://localhost:27017
DATABASE_NAME=cyberverse
API_BASE_URL=http://localhost:8000
```

## Running the Orchestration Service

To run this template as an independent orchestrator on port `8009`:
```bash
uv run python -m uvicorn src.email_threat_template.main:app --host 0.0.0.0 --port 8009 --reload
```

## Testing Instructions

1. **Start Backend Agents**: Ensure the Phishing, Malware, and Incident Response agents are running and accessible via `API_BASE_URL`.
2. **Run Orchestrator**: Start this orchestrator (see command above).
3. **Submit a Request**:
   Use `curl` or Postman to submit an email analysis request:

   *Test with text only:*
   ```bash
   curl -X POST "http://localhost:8009/api/template/email-threat-investigation" \
     -F "url_or_text=Suspicious email body claiming to be your CEO." \
     -F "notify_email=test@example.com"
   ```

   *Test with an EML file attachment:*
   ```bash
   curl -X POST "http://localhost:8009/api/template/email-threat-investigation" \
     -F "file=@/path/to/suspicious.eml" \
     -F "notify_email=test@example.com"
   ```

4. **Verify Email & MongoDB**: Check your inbox for the alert email and verify that the `email_threat_alerts` collection in MongoDB has the `email_sent: true` flag to prevent duplicates on subsequent identical `investigation_id` requests.
5. **Frontend Canvas**: You can drag the "Email Threat Investigation" template onto the Canvas UI to visualize the 6-node flow.
