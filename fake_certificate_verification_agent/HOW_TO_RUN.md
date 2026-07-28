# 🚀 CyberVerse AI Multi-Agent Cybersecurity Platform - How to Run Guide

Welcome to **CyberVerse**, the AI-Powered Multi-Agent Cybersecurity & Digital Trust Platform.

---

## 📋 System Requirements

- **OS**: Windows, macOS, or Linux
- **Python**: 3.10 to 3.13 installed
- **MongoDB Compass / MongoDB Atlas**: (Optional, default connects to local MongoDB or fallback JSON database)

---

## ⚙️ 1. Environment Setup & Dependencies

1. Open your terminal in PowerShell and navigate to the project directory:
   ```powershell
   cd "d:\Downloads\fake_certificate_verification_agent_v1_crewai-project (1)"
   ```

2. Create `.env` file (if not already present):
   ```powershell
   cp .env.example .env
   ```

3. Install required Python packages:
   ```powershell
   pip install -e .
   ```

---

## 🚀 2. Running the Server (Native Local Python Execution)

Launch the FastAPI backend & web dashboard directly using Python and `uvicorn`:

```powershell
$env:PYTHONIOENCODING="utf-8"; python -m uvicorn src.fake_certificate_verification_agent.main:app --reload --port 8000
```

Once started, access:
- 🌐 **Web Dashboard UI**: [http://localhost:8000](http://localhost:8000)
- 📜 **Interactive API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- 💚 **Backend Health Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)

---

## 🧠 3. Testing CyberVerse Agents & Features

1. Open **[http://localhost:8000](http://localhost:8000)**.
2. Select **🧠 Master Orchestrator** in the navigation bar:
   - Type a query prompt (e.g. `Analyze IP 185.220.101.5` or `Verify degree for Alexander Vance`).
   - Or click any of the **Smart Scenario Chips** (`Degree Cert`, `Passport & Selfie`, `Malware .exe`, `Threat IP`).
   - Click **Run Master Orchestrator**.
3. View real-time sub-agent execution, routing diagnostics, and security score.
4. Click **Export Report (PDF/HTML)** or **Export JSON** to download official audit reports!

---

## 📡 4. Master REST APIs Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check & list of 10 active agents |
| `POST` | `/api/auth/register` | Register new user account |
| `POST` | `/api/auth/login` | Authenticate user and issue JWT |
| `POST` | `/api/orchestrator/analyze` | Master Orchestrator analysis & dispatch |
| `POST` | `/api/verify/certificate` | 9-layer certificate forensics |
| `POST` | `/api/verify/identity` | 9-layer identity & biometric forensics |
| `POST` | `/api/analyze/malware` | Static PE & YARA malware analysis |
| `POST` | `/api/analyze/threat` | IP / URL reputation & AbuseIPDB lookup |
| `POST` | `/api/analyze/phishing` | Typosquatting & SSL check |
| `POST` | `/api/audit/privacy` | GDPR/DPDP PII audit |
| `POST` | `/api/advise/password` | Entropy & breach database check |
| `GET` | `/api/reports` | List historical audit reports |
| `GET` | `/api/reports/{id}/export` | Export printable HTML/PDF SOC report |
| `GET` | `/api/reports/{id}/json` | Export raw structured JSON report |
| `GET` | `/api/admin/stats` | Platform analytics & threat counters |
| `GET` | `/api/admin/agents` | Real-time 10-agent health monitor |
