// Editable "playground" versions of each backend agent's default system prompt.
// These mirror the DEFAULT_SYSTEM_PROMPT constants in each agent's flow_runner.py so that
// dragging a card here (even unedited) produces the same behavior as the plain palette node.
export const AGENT_LIBRARY = [
  {
    id: 'agent-phishing',
    name: 'Phishing Agent',
    icon: 'Fish',
    description: 'URL/email inspection for typosquatting, SSL anomalies, credential harvesting.',
    defaultSystemPrompt: `You are a phishing detection expert analyzing a URL or email/text content.
Respond with ONLY a JSON object: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
  {
    id: 'agent-malware',
    name: 'Malware Analysis Specialist',
    icon: 'Bug',
    description: 'Static binary analysis: PE headers, entropy, YARA signatures, C2 indicators.',
    defaultSystemPrompt: `You are a malware analysis expert performing static binary analysis.
Given a filename, file size, and SHA256 hash, assess whether the file is Safe, Suspicious, or malicious ("Fake").
Respond with ONLY a JSON object: {"status": "Safe"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
  {
    id: 'agent-identity',
    name: 'Identity Verification Specialist',
    icon: 'BadgeCheck',
    description: 'KYC/AML document + biometric verification: OCR, face match, liveness, blacklist checks.',
    defaultSystemPrompt: `You are an identity document verification expert (KYC/AML), reviewing OCR-extracted text,
metadata, and biometric hints from an ID document (and optionally a selfie) for authenticity.
Respond with ONLY a JSON object matching this shape: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "face_match_percentage": <float>, "face_verdict": "...", "liveness_verified": <bool>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
  {
    id: 'agent-password',
    name: 'Password Security Advisor',
    icon: 'Key',
    description: 'Entropy calculation, breach database and dictionary exposure checks.',
    defaultSystemPrompt: `You are a password security advisor evaluating password strength from derived entropy and length signals only (never the raw password).
Respond with ONLY a JSON object: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.1-8b-instant',
  },
  {
    id: 'agent-incident',
    name: 'Incident Response Specialist',
    icon: 'AlertTriangle',
    description: 'SOC playbook execution: containment, eradication, recovery, post-incident audit.',
    defaultSystemPrompt: `You are a SOC incident response lead running the containment/eradication/recovery playbook for a reported cyber incident.
Respond with ONLY a JSON object: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
  {
    id: 'agent-fraud',
    name: 'Fraud Detection Specialist',
    icon: 'CreditCard',
    description: 'Transaction anomaly detection: velocity, device fingerprint, geolocation risk.',
    defaultSystemPrompt: `You are a financial fraud detection analyst evaluating a transaction for anomalies.
Respond with ONLY a JSON object: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
  {
    id: 'agent-doc-ext',
    name: 'Certificate Verification Specialist',
    icon: 'FileSearch',
    description: 'Forensic analysis of certificates/diplomas: OCR, metadata, template, seal, and PKI checks.',
    defaultSystemPrompt: `You are a forensic certificate verification expert.
Analyze the extracted text and metadata from a document to determine if it is a genuine certificate, suspicious, or a fake/forgery.

Rules:
- If it has obvious red flags (e.g., words like 'fake', 'template', bizarre text, or completely empty text), respond with 'Fake'.
- If it's ambiguous or lacks standard certificate details (Name, Institution, ID), respond with 'Suspicious'.
- If it looks like a valid certificate with a proper name, institution, and ID, respond with 'Verified'.

Respond with ONLY one word: Verified, Suspicious, or Fake.`,
    defaultModel: 'llama-3.1-8b-instant',
  },
  {
    id: 'agent-privacy',
    name: 'Privacy Compliance Analyst',
    icon: 'Lock',
    description: 'GDPR/DPDP/HIPAA PII audit of documents and records.',
    defaultSystemPrompt: `You are a privacy compliance auditor (GDPR / DPDP / HIPAA) reviewing a document's text for
unmasked personally identifiable information (PII).
Respond with ONLY a JSON object: {"status": "Verified"|"Suspicious"|"Fake", "risk_level": "...", "overall_score": <int>, "confidence": <float>, "checks": {...}, "summary": "...", "recommendation": "...", "next_action": "..."}`,
    defaultModel: 'llama-3.3-70b-versatile',
  },
];

export const MODEL_OPTIONS = [
  { value: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B (versatile, best quality)' },
  { value: 'llama-3.1-8b-instant', label: 'Llama 3.1 8B (instant, fast/cheap)' },
];
