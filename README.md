# CyberVerse — Enterprise Multi-Agent Cybersecurity Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6.svg)](https://www.typescriptlang.org/)
[![CrewAI](https://img.shields.io/badge/CrewAI-v1.8+-orange.svg)](https://crewai.com/)

**CyberVerse** is an enterprise-grade multi-agent cybersecurity platform. It aggregates 44 specialized security analysis tools across 9 AI specialist domains into a unified threat intelligence and incident response orchestrator with a FastAPI REST backend and a dark-mode React dashboard.

---

## 🏛️ System Architecture

```
                               ┌───────────────────────────────────────────────┐
                               │           React + TypeScript Dashboard         │
                               │        (Vite, Tailwind v4, Recharts)          │
                               └───────────────────────┬───────────────────────┘
                                                       │  REST / JWT
                                                       ▼
                               ┌───────────────────────────────────────────────┐
                               │                 FastAPI Backend               │
                               │  FastAPI REST API with JWT authentication,    │
                               │  OpenAPI/Swagger docs, CORS, background task  │
                               │  execution & structured report persistence    │
                               └───────────────────────┬───────────────────────┘
                                                       │
                                                       ▼
                               ┌───────────────────────────────────────────────┐
                               │          Multi-Agent Orchestrator             │
                               │      (CrewAI Flow + ThreadPoolExecutor)       │
                               └───────────────────────┬───────────────────────┘
                                                       │
    ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
    ▼                   ▼                   ▼                   ▼                   ▼
 Certificate         Privacy             Malware             Threat              Identity
Verification        Compliance           Analysis           Detection           Verification
 Specialist          Analyst            Specialist          Specialist           Specialist
 ┌─────────┐         ┌─────────┐         ┌─────────┐         ┌─────────┐         ┌─────────┐
 │ 5 Tools │         │ 4 Tools │         │ 5 Tools │         │ 5 Tools │         │ 5 Tools │
 └─────────┘         └─────────┘         └─────────┘         └─────────┘         └─────────┘

    ┌───────────────────┬───────────────────┬───────────────────┐
    ▼                   ▼                   ▼                   ▼
  Fraud              Phishing            Password            Incident
Detection           Detection            Security            Response
Specialist          Specialist           Advisor            Specialist
 ┌─────────┐         ┌─────────┐         ┌─────────┐         ┌─────────┐
 │ 5 Tools │         │ 5 Tools │         │ 5 Tools │         │ 5 Tools │
 └─────────┘         └─────────┘         └─────────┘         └─────────┘
```

---

## 🛡️ Key Features

### 1. 44 Specialized Security Analysis Tools Across 9 Domains
- **Certificate Verification Specialist**: OCR document parsing, metadata extraction, QR code validation, digital signature verification, certificate tampering detection.
- **Privacy Compliance Analyst**: PII detection, secret scanning (API keys/tokens), compliance validation (GDPR/HIPAA/PCI-DSS), privacy risk assessment.
- **Malware Analysis Specialist**: Cryptographic file hashing, YARA pattern scanning, PE binary header analysis, VirusTotal intelligence integration, malware risk scoring.
- **Threat Detection Specialist**: IP reputation, URL reputation, DNS record security analysis, IOC extraction & verification, threat risk scoring.
- **Identity Verification Specialist**: Identity document verification, facial biometrics analysis, liveness detection, cross-document identity consistency, identity risk scoring.
- **Fraud Detection Specialist**: Transaction anomaly analysis, behavioral biometrics profiling, device fingerprinting, account takeover (ATO) detection, fraud risk scoring.
- **Phishing Detection Specialist**: RFC-2822 email header inspection, URL structure inspection, domain reputation & typosquatting detection, email body content analysis, phishing risk scoring.
- **Password Security Advisor**: Password strength entropy analysis, enterprise password policy enforcement, k-anonymity data breach exposure lookups (HIBP), MFA readiness assessment, password risk scoring.
- **Incident Response Specialist**: Security alert taxonomy classification, MITRE ATT&CK technique mapping ($Txxxx$), read-only forensic evidence manifest creation, prioritized containment playbooks (P1–P5), enterprise incident response aggregation.

### 2. Multi-Agent Orchestration Engine
- Built on **CrewAI Flows** to dispatch security analysis across selected specialists concurrently using Python's `ThreadPoolExecutor`.
- Platform-level risk calculation incorporating weighted domain scores, critical threat escalation triggers, and confidence penalty adjustments for partial execution failures.

### 3. Enterprise FastAPI REST Backend
- FastAPI-based REST API with JWT authentication, OpenAPI/Swagger documentation, CORS support, background task execution, and structured report persistence (in-memory + JSON storage).

### 4. Interactive React Dashboard
- Modern dark-mode interface built with Vite, React 19, TypeScript, and Tailwind CSS v4.
- Features animated SVG Risk Gauges, Recharts Radar & Bar breakdown charts, evidence tables, priority-ordered action items, and executive summaries.

---

## 🛠️ Quick Start

### Prerequisites
- Python >= 3.10
- Node.js >= 18

### 1. Backend Setup & Tests
```bash
# Run Orchestrator Unit Tests
python -m unittest tests/test_orchestrator.py -v

# Run Specialist End-to-End Tests
python -m unittest tests/test_incident_response_end_to_end.py -v
python -m unittest tests/test_password_security_end_to_end.py -v

# Start FastAPI Server
python -m uvicorn cyberverse.api.main:app --reload --port 8000
```
Swagger API documentation will be available at `http://localhost:8000/docs`.

### 2. Frontend Setup & Build
```bash
cd frontend

# Install Dependencies
npm install

# Run Development Server
npm run dev

# Production Build Verification
npm run build
```
Dashboard will be available at `http://localhost:5173`.

---

## 📄 License
Licensed under the [MIT License](LICENSE).
