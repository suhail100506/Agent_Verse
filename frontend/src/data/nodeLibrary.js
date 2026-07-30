export const NODE_CATEGORIES = [
  { id: 'all', name: 'All Components', icon: 'Layers', count: 34 },
  { id: 'triggers', name: 'Triggers & Webhooks', icon: 'Zap', count: 4 },
  { id: 'ai', name: 'AI Agents & LLMs', icon: 'Bot', count: 7 },
  { id: 'security', name: 'Security & Forensics', icon: 'ShieldAlert', count: 9 },
  { id: 'logic', name: 'Logic & Control Flow', icon: 'GitBranch', count: 4 },
  { id: 'database', name: 'Databases & Storage', icon: 'Database', count: 3 },
  { id: 'communication', name: 'Communication & Cloud', icon: 'Send', count: 4 },
  { id: 'code', name: 'Code & Data Transform', icon: 'Code2', count: 3 },
  { id: 'human', name: 'Human Approval & SOC', icon: 'UserCheck', count: 2 }
];

export const NODE_LIBRARY = [
  // TRIGGERS
  {
    id: 'node-file-upload',
    category: 'triggers',
    name: 'User Payload Ingest',
    subtitle: 'Payload & Document Trigger Input',
    icon: 'FileUp',
    badge: 'Trigger',
    badgeColor: 'indigo',
    description: 'Receive document uploads (diplomas, certificates, executables, logs) or text payload queries for workflow execution.',
    inputs: [],
    outputs: ['payload'],
    isIngestNode: true,
    defaultData: {
      label: 'User Payload Ingest',
      subtitle: 'Payload Trigger Input',
      icon: '📄',
      isTextBox: true,
      status: 'idle'
    }
  },
  {
    id: 'trigger-webhook',
    category: 'triggers',
    name: 'Webhook Listener',
    subtitle: 'HTTP POST / GET Endpoint',
    icon: 'Radio',
    badge: 'Trigger',
    badgeColor: 'indigo',
    description: 'Listen for real-time HTTP webhooks from external services or microservices.',
    inputs: [],
    outputs: ['payload', 'headers'],
    defaultData: {
      label: 'Webhook Listener',
      subtitle: 'HTTP Endpoint Trigger',
      icon: '📡',
      endpoint: '/api/v1/webhook/ingest',
      method: 'POST',
      isWebhookTrigger: true
    }
  },
  {
    id: 'trigger-schedule',
    category: 'triggers',
    name: 'Cron Scheduler',
    subtitle: 'Periodic Execution Trigger',
    icon: 'Clock',
    badge: 'Trigger',
    badgeColor: 'indigo',
    description: 'Trigger automated security scans on scheduled intervals.',
    inputs: [],
    outputs: ['timestamp', 'executionId'],
    defaultData: {
      label: 'Cron Scheduler',
      subtitle: 'Periodic Interval Trigger',
      icon: '⏰',
      cron: '*/15 * * * *'
    }
  },

  // AI & LLMS
  {
    id: 'agent-orchestrator',
    category: 'ai',
    name: 'Master Cyber Orchestrator',
    subtitle: 'Autonomous Multi-Agent Router',
    icon: 'Cpu',
    badge: 'AI Core',
    badgeColor: 'cyan',
    description: 'Analyzes user intent, dispatches tasks to 10 specialized sub-agents, and synthesizes final risk report.',
    inputs: ['payload'],
    outputs: ['analysis', 'riskScore', 'dispatchedAgents'],
    defaultData: {
      id: 'agent-decision',
      label: 'Master Decision Agent',
      subtitle: 'Synthesizer & Risk Assessment',
      icon: '🧠',
      inputLabel: 'Multi-Agent Synthesis'
    }
  },
  {
    id: 'agent-doc-ext',
    category: 'ai',
    name: 'Document Extraction Agent',
    subtitle: 'OCR & Metadata Parsing',
    icon: 'FileSearch',
    badge: 'AI Vision',
    badgeColor: 'cyan',
    description: 'Extracts structured JSON fields, seal placement, layout metrics, and university metadata from diplomas.',
    inputs: ['document'],
    outputs: ['structuredFields', 'confidence'],
    defaultData: {
      id: 'agent-doc-ext',
      label: 'Document Extraction Agent',
      subtitle: 'OCR & Metadata Parsing',
      icon: '🤖',
      inputLabel: 'PDF Document Required'
    }
  },
  {
    id: 'agent-auth-ver',
    category: 'ai',
    name: 'Authenticity Verification',
    subtitle: 'PKI Root & Blockchain Check',
    icon: 'BadgeCheck',
    badge: 'AI Agent',
    badgeColor: 'cyan',
    description: 'Cross-verifies student IDs, certificate serial numbers against national registries and PKI roots.',
    inputs: ['certData'],
    outputs: ['isVerified', 'pkiStatus'],
    defaultData: {
      id: 'agent-auth-ver',
      label: 'Authenticity Verification Agent',
      subtitle: 'PKI Root & Registry Check',
      icon: '🛡️',
      inputLabel: 'Cert ID & Candidate Required'
    }
  },

  {
    id: 'agent-identity',
    category: 'ai',
    name: 'Identity Verification Agent',
    subtitle: 'KYC/AML Document & Biometric Check',
    icon: 'BadgeCheck',
    badge: 'AI Agent',
    badgeColor: 'cyan',
    description: 'Verifies ID documents (passport, license) and optional selfie for OCR, face match, liveness, and blacklist checks.',
    inputs: ['documentFile', 'selfieFile'],
    outputs: ['isVerified', 'faceMatchPercentage'],
    defaultData: {
      id: 'agent-identity',
      label: 'Identity Verification Agent',
      subtitle: 'KYC/AML Document & Biometric Check',
      icon: '🪪',
      inputLabel: 'ID Document (+ optional selfie) Required'
    }
  },

  // SECURITY & FORENSICS
  {
    id: 'agent-vis-forensics',
    category: 'security',
    name: 'Visual Forensics Agent',
    subtitle: 'ELA & Font Splicing Forensic',
    icon: 'Eye',
    badge: 'Forensics',
    badgeColor: 'rose',
    description: 'Detects Photoshop manipulation, Error Level Analysis (ELA) anomalies, font splicing, and pixel noise.',
    inputs: ['imageFile'],
    outputs: ['elaScore', 'tamperDetected'],
    defaultData: {
      id: 'agent-vis-forensics',
      label: 'Visual Forensics Agent',
      subtitle: 'ELA & Font Splicing Forensic',
      icon: '👁️',
      inputLabel: 'Diploma Image / Seal Required'
    }
  },
  {
    id: 'agent-malware',
    category: 'security',
    name: 'Malware Analyzer Agent',
    subtitle: 'PE & YARA Behavioral Audit',
    icon: 'Bug',
    badge: 'Malware',
    badgeColor: 'rose',
    description: 'Static binary analysis of executables, PE header inspection, entropy scores, and YARA signature matches.',
    inputs: ['binaryFile'],
    outputs: ['threatScore', 'yaraMatches', 'isMalicious'],
    defaultData: {
      id: 'agent-malware',
      label: 'Malware Analyzer Agent',
      subtitle: 'PE & YARA Behavioral Audit',
      icon: '🦠',
      inputLabel: 'Binary Executable (.exe) Required'
    }
  },
  {
    id: 'agent-threat',
    category: 'security',
    name: 'Cyber Threat Detection',
    subtitle: 'IP Reputation & Abuse Lookup',
    icon: 'Globe',
    badge: 'Threat Intel',
    badgeColor: 'rose',
    description: 'Checks target IP addresses or domain names against AbuseIPDB, VirusTotal, and active C2 feeds.',
    inputs: ['targetIp'],
    outputs: ['abuseConfidenceScore', 'isp', 'country'],
    defaultData: {
      id: 'agent-threat',
      label: 'Cyber Threat Detection Agent',
      subtitle: 'IP Reputation & Abuse Lookup',
      icon: '🌐',
      inputLabel: 'Target IP Address Required'
    }
  },
  {
    id: 'agent-phishing',
    category: 'security',
    name: 'Phishing Detection Agent',
    subtitle: 'SSL & Typosquatting Check',
    icon: 'Fish',
    badge: 'Phishing',
    badgeColor: 'rose',
    description: 'Inspects email contents and URLs for typosquatting, suspicious domain age, and brand spoofing.',
    inputs: ['urlOrText'],
    outputs: ['isPhishing', 'typosquatMatch', 'alertStatus'],
    defaultData: {
      id: 'agent-phishing',
      label: 'Phishing Detection Agent',
      subtitle: 'SSL & Typosquatting Check',
      icon: '🎣',
      inputLabel: 'Target URL Domain Required'
    }
  },
  {
    id: 'agent-privacy',
    category: 'security',
    name: 'Privacy Compliance Agent',
    subtitle: 'GDPR / DPDP PII Audit',
    icon: 'Lock',
    badge: 'Compliance',
    badgeColor: 'amber',
    description: 'Scans documents for unmasked PII (SSN, Passport, Credit Card, Email) and evaluates compliance risks.',
    inputs: ['textContent'],
    outputs: ['piiFoundCount', 'isCompliant'],
    defaultData: {
      id: 'agent-privacy',
      label: 'Privacy Compliance Agent',
      subtitle: 'GDPR / DPDP PII Audit',
      icon: '🔒',
      inputLabel: 'Text Document / Record Required'
    }
  },
  {
    id: 'agent-password',
    category: 'security',
    name: 'Password Security Advisor',
    subtitle: 'Entropy & Breach Database',
    icon: 'Key',
    badge: 'Auth Sec',
    badgeColor: 'amber',
    description: 'Calculates bit entropy, checks k-Anonymity breach hashes, and evaluates password strength.',
    inputs: ['passwordStr'],
    outputs: ['entropyBits', 'pwnedCount'],
    defaultData: {
      id: 'agent-password',
      label: 'Password Security Advisor',
      subtitle: 'Entropy & Breach Database',
      icon: '🔑',
      inputLabel: 'Password String Required'
    }
  },
  {
    id: 'agent-fraud',
    category: 'security',
    name: 'Fraud Detection Agent',
    subtitle: 'Transaction Anomaly & Geo Risk',
    icon: 'CreditCard',
    badge: 'Fraud AI',
    badgeColor: 'rose',
    description: 'Calculates anomaly vectors for monetary transactions based on location, velocity, and amount.',
    inputs: ['transactionData'],
    outputs: ['fraudRiskScore', 'isAnomaly'],
    defaultData: {
      id: 'agent-fraud',
      label: 'Fraud Detection Agent',
      subtitle: 'Transaction Anomaly & Geo Risk',
      icon: '💳',
      inputLabel: 'Amount ($) & Location Required'
    }
  },
  {
    id: 'agent-incident',
    category: 'security',
    name: 'Incident Response Agent',
    subtitle: 'SOC Playbooks & Containment',
    icon: 'AlertTriangle',
    badge: 'SOC Auto',
    badgeColor: 'rose',
    description: 'Triggers automated incident playbooks, isolates endpoints, and generates official SOC incident tickets.',
    inputs: ['alertDetails'],
    outputs: ['incidentId', 'playbookExecuted'],
    defaultData: {
      id: 'agent-incident',
      label: 'Incident Response Agent',
      subtitle: 'SOC Playbooks & Containment',
      icon: '🚨',
      inputLabel: 'Incident Title Required'
    }
  },

  {
    id: 'agent-social-eng',
    category: 'security',
    name: 'Social Engineering / Deepfake Detection',
    subtitle: 'Manipulation Tactic & Media Tamper Check',
    icon: 'Drama',
    badge: 'Social Eng',
    badgeColor: 'rose',
    description: 'Detects urgency/pressure language, authority impersonation, financial-request patterns, and deepfake/media tampering indicators.',
    inputs: ['textContent', 'mediaFile'],
    outputs: ['isSocialEngineering', 'riskLevel'],
    defaultData: {
      id: 'agent-social-eng',
      label: 'Social Engineering / Deepfake Agent',
      subtitle: 'Manipulation Tactic & Media Tamper Check',
      icon: '🎭',
      inputLabel: 'Text / Message / Media Required'
    }
  },

  // LOGIC & FLOW CONTROL
  {
    id: 'logic-if',
    category: 'logic',
    name: 'If / Else Branch',
    subtitle: 'Conditional Path Evaluator',
    icon: 'GitCommit',
    badge: 'Control',
    badgeColor: 'emerald',
    description: 'Splits execution into True / False branches based on evaluation condition.',
    inputs: ['input'],
    outputs: ['truePath', 'falsePath'],
    defaultData: {
      id: 'logic-if',
      label: 'If / Else Condition',
      subtitle: 'Branch: riskScore > 75',
      icon: '🔀',
      isLogicNode: true,
      conditionField: 'riskScore',
      conditionOperator: '>',
      conditionValue: '75'
    }
  },
  {
    id: 'logic-loop',
    category: 'logic',
    name: 'Loop Over Items',
    subtitle: 'Iterate Array Items',
    icon: 'Repeat',
    badge: 'Control',
    badgeColor: 'emerald',
    description: 'Iterates through each element in an array and outputs items individually.',
    inputs: ['array'],
    outputs: ['loopItem', 'onDone'],
    defaultData: {
      id: 'logic-loop',
      label: 'Loop Over Items',
      subtitle: 'Iterates 5 items',
      icon: '🔁',
      isLoopNode: true
    }
  },

  // DATABASE & STORAGE
  {
    id: 'node-mongodb',
    category: 'database',
    name: 'MongoDB Audit Logs',
    subtitle: 'Persistent Database Store',
    icon: 'Database',
    badge: 'Storage',
    badgeColor: 'teal',
    description: 'Saves execution audit logs and risk reports into persistent MongoDB collections.',
    inputs: ['logEntry'],
    outputs: ['insertedId', 'success'],
    defaultData: {
      id: 'node-mongodb',
      label: 'MongoDB Audit Logs',
      subtitle: 'Persistent Database Store',
      icon: '🍃',
      inputLabel: 'Database Persistence'
    }
  },

  // CODE & TRANSFORM
  {
    id: 'code-python',
    category: 'code',
    name: 'Python Code Box',
    subtitle: 'Execute Custom Python Logic',
    icon: 'Code2',
    badge: 'Code',
    badgeColor: 'violet',
    description: 'Runs custom Python logic with access to input payload variables.',
    inputs: ['payload'],
    outputs: ['result'],
    defaultData: {
      id: 'code-python',
      label: 'Python Data Script',
      subtitle: 'Filter & Normalize Scores',
      icon: '🐍',
      isCodeNode: true
    }
  },

  // OUTPUT / REPORT
  {
    id: 'node-final-report',
    category: 'human',
    name: 'Final Security Report',
    subtitle: 'JSON & PDF SOC Exporter',
    icon: 'FileCheck2',
    badge: 'Output',
    badgeColor: 'emerald',
    description: 'Compiles multi-agent forensic outputs into printable PDF and structured JSON reports.',
    inputs: ['reportData'],
    outputs: ['pdfUrl', 'jsonExport'],
    defaultData: {
      id: 'node-final-report',
      label: 'Final Security Report',
      subtitle: 'JSON & PDF SOC Exporter',
      icon: '📋',
      inputLabel: 'Report Generator'
    }
  }
];

