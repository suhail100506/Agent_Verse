# Phishing Detection Agent

An intelligent, production-ready AI agent that determines whether an email is a phishing attempt using heuristic analysis and CrewAI powered by Gemini.

## Features
- **Heuristic Analysis**: Detects typo-squatting, fake domains, urgent subjects, insecure links, and IP-based URLs.
- **Header Analysis**: Parses SPF, DKIM, and DMARC failures.
- **AI Reasoning**: Uses CrewAI with Gemini to evaluate social engineering, business email compromise, and credential harvesting intents.
- **Risk Scoring**: Weighted system categorizing threats into Safe, Medium, High, and Critical.
- **MongoDB Logging**: Asynchronously logs inputs, execution times, and results for auditing.

## Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Environment Variables**
   Create a `.env` file in the root based on `.env.example`:
   ```env
   GEMINI_API_KEY=your_gemini_api_key
   GEMINI_MODEL=gemini/gemini-1.5-flash
   MONGODB_URI=mongodb://localhost:27017
   DATABASE_NAME=cyberverse_agents
   ```

3. **Run the Application**
   ```bash
   uvicorn src.phishing_detection_agent.main:app --host 0.0.0.0 --port 8001 --reload
   ```

## Endpoints

### 1. Health Check
`GET /api/phishing/health`
Checks if the service is running.

**Response:**
```json
{
  "status": "ok",
  "service": "Phishing Detection Agent"
}
```

### 2. Analyze Email
`POST /api/phishing/analyze`
Analyzes email metadata and content to detect phishing indicators.

**Request Example:**
```json
{
    "sender": "microsoft-security@micr0soft-support.com",
    "subject": "Verify your Microsoft account immediately",
    "body": "Click the link below to avoid suspension.",
    "headers": "spf=fail; dkim=fail",
    "urls": [
        "http://micr0soft-login.com"
    ]
}
```

**Response Example:**
```json
{
    "success": true,
    "agent": "Phishing Detection Agent",
    "risk_score": 94,
    "risk_level": "Critical",
    "attack_type": "Credential Theft",
    "confidence": 98,
    "findings": [
        "Typo-squatting detected in domain: micr0soft-support.com",
        "Urgent language detected in subject: 'immediately'",
        "HTTP (insecure) link found",
        "Suspicious URL resembling microsoft.com detected",
        "SPF validation failed",
        "DKIM signature invalid",
        "AI Assessment: High risk of credential harvesting."
    ],
    "recommendations": [
        "Do not click the link",
        "Block sender",
        "Quarantine email"
    ],
    "next_step": "Malware Analysis Agent"
}
```
