# Incident Response Agent

This is a standalone AI Agent built with FastAPI and CrewAI to process cyber incidents (such as phishing or malware analysis findings), classify them, assess severity, map to MITRE ATT&CK, and formulate containment and recovery plans.

## Tech Stack
- Python 3.12+
- FastAPI
- CrewAI
- Gemini API (via LangChain integration)
- MongoDB
- Pydantic

## Installation

```bash
cd backend
pip install -r src/incident_response_agent/requirements.txt
```

Ensure you have a `.env` file either in the project root or the `src` directory matching the format found in `.env.example`.

## Running the Agent

Start the standalone API server:
```bash
uv run python -m uvicorn src.incident_response_agent.main:app --reload --port 8008
```

## API Usage

**POST /api/incident/respond**

Accepts structured JSON data about findings and returns an actionable response plan.

Example Request:
```bash
curl -X POST http://localhost:8008/api/incident/respond \
     -H "Content-Type: application/json" \
     -d @src/incident_response_agent/sample_request.json
```

Example Response:
```json
{
  "success": true,
  "agent": "Incident Response Agent",
  "incident_type": "Business Email Compromise",
  "severity": "Critical",
  "business_impact": "High financial and data exposure risk.",
  "mitre_attack": [
    {
      "id": "T1566",
      "name": "Phishing"
    }
  ],
  "containment": [
    "Quarantine email",
    "Block sender",
    "Isolate affected endpoint"
  ],
  "recovery": [
    "Reset credentials",
    "Run full malware scan",
    "Monitor authentication logs"
  ],
  "executive_summary": "A high-risk phishing email with a malicious attachment was detected. Immediate containment is recommended to prevent credential compromise and malware execution.",
  "confidence": 0.95
}
```
