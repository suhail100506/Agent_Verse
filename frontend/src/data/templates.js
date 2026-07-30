// Real, loadable {nodes, edges} graphs for each of the 11 templates:
// 10 single-agent workflows (trigger -> agent -> report) + 1 full master orchestration.

const ingestNode = (idSuffix, x, y) => ({
  id: `t-${idSuffix}-in`,
  type: 'agentNode',
  position: { x, y },
  data: {
    id: 'node-user-upload',
    label: 'Payload Ingest',
    subtitle: 'Payload Trigger Input',
    icon: '📄',
    isTextBox: true,
    inputLabel: 'User Payload',
    status: 'idle'
  }
});

const reportNode = (idSuffix, x, y) => ({
  id: `t-${idSuffix}-out`,
  type: 'agentNode',
  position: { x, y },
  data: {
    id: 'node-final-report',
    label: 'Final Security Report',
    subtitle: 'JSON & PDF SOC Exporter',
    icon: '📋',
    inputLabel: 'Report Generator',
    status: 'idle'
  }
});

const agentNode = (idSuffix, agentId, label, subtitle, icon, inputLabel, x, y) => ({
  id: `t-${idSuffix}-agent`,
  type: 'agentNode',
  position: { x, y },
  data: { id: agentId, label, subtitle, icon, inputLabel, status: 'idle' }
});

const edge = (id, source, target) => ({
  id,
  source,
  target,
  animated: true,
  style: { stroke: '#6366f1', strokeWidth: 2 }
});

function singleAgentTemplate({ id, title, description, badge, agentId, agentLabel, agentSubtitle, icon, inputLabel }) {
  const nodes = [
    ingestNode(id, 80, 150),
    agentNode(id, agentId, agentLabel, agentSubtitle, icon, inputLabel, 460, 150),
    reportNode(id, 840, 150),
  ];
  const edges = [
    edge(`e-${id}-1`, nodes[0].id, nodes[1].id),
    edge(`e-${id}-2`, nodes[1].id, nodes[2].id),
  ];
  return { id, title, description, badge, category: 'Single-Agent', nodeCount: 3, nodes, edges };
}

const SINGLE_AGENT_TEMPLATES = [
  singleAgentTemplate({
    id: 'template-certificate-verification',
    title: 'Certificate & Diploma Forensics',
    description: 'OCR extraction, template/seal/PKI checks, and Groq-backed forgery verdict for certificates and diplomas.',
    badge: 'Forensic Flow',
    agentId: 'agent-doc-ext',
    agentLabel: 'Fake Certificate Verification Agent',
    agentSubtitle: 'OCR & PKI Forensics',
    icon: '🤖',
    inputLabel: 'PDF/Image Certificate Required',
  }),
  singleAgentTemplate({
    id: 'template-identity-verification',
    title: 'Identity Document & Biometric Verification',
    description: 'KYC/AML pipeline: OCR, face match, liveness, and blacklist screening for passports and ID cards.',
    badge: 'KYC/AML',
    agentId: 'agent-identity',
    agentLabel: 'Identity Verification Agent',
    agentSubtitle: 'KYC/AML Document & Biometric Check',
    icon: '🪪',
    inputLabel: 'ID Document Required',
  }),
  singleAgentTemplate({
    id: 'template-malware-analysis',
    title: 'Malware Static Analysis',
    description: 'PE header inspection, entropy scoring, YARA signature matching, and C2 indicator detection.',
    badge: 'Malware',
    agentId: 'agent-malware',
    agentLabel: 'Malware Analyzer Agent',
    agentSubtitle: 'PE & YARA Behavioral Audit',
    icon: '🦠',
    inputLabel: 'Binary Executable Required',
  }),
  singleAgentTemplate({
    id: 'template-threat-detection',
    title: 'IP/Domain Threat Intelligence',
    description: 'AbuseIPDB-style reputation scoring, threat categorization, and port scan review for IPs/domains.',
    badge: 'Threat Intel',
    agentId: 'agent-threat',
    agentLabel: 'Cyber Threat Detection Agent',
    agentSubtitle: 'IP Reputation & Abuse Lookup',
    icon: '🌐',
    inputLabel: 'Target IP/Domain Required',
  }),
  singleAgentTemplate({
    id: 'template-phishing-detection',
    title: 'Phishing URL & Email Triage',
    description: 'Typosquatting, SSL validity, DKIM/SPF, and credential-harvesting checks with automated email alerting.',
    badge: 'Phishing',
    agentId: 'agent-phishing',
    agentLabel: 'Phishing Detection Agent',
    agentSubtitle: 'SSL & Typosquatting Check',
    icon: '🎣',
    inputLabel: 'URL or Email Text Required',
  }),
  singleAgentTemplate({
    id: 'template-privacy-compliance',
    title: 'Privacy / PII Compliance Audit',
    description: 'GDPR / DPDP / HIPAA scan for unmasked PII (SSNs, cards, emails) across documents and records.',
    badge: 'Compliance',
    agentId: 'agent-privacy',
    agentLabel: 'Privacy Compliance Agent',
    agentSubtitle: 'GDPR / DPDP PII Audit',
    icon: '🔒',
    inputLabel: 'Text Document Required',
  }),
  singleAgentTemplate({
    id: 'template-password-advisor',
    title: 'Password Strength Advisory',
    description: 'Entropy calculation, dictionary exposure, and breach-database checks for a submitted password.',
    badge: 'Auth Sec',
    agentId: 'agent-password',
    agentLabel: 'Password Security Advisor',
    agentSubtitle: 'Entropy & Breach Database',
    icon: '🔑',
    inputLabel: 'Password String Required',
  }),
  singleAgentTemplate({
    id: 'template-fraud-detection',
    title: 'Transaction Fraud Detection',
    description: 'Behavioral analytics, device fingerprinting, velocity, and geolocation-anomaly scoring for a transaction.',
    badge: 'Fraud AI',
    agentId: 'agent-fraud',
    agentLabel: 'Fraud Detection Agent',
    agentSubtitle: 'Transaction Anomaly & Geo Risk',
    icon: '💳',
    inputLabel: 'Transaction Details Required',
  }),
  singleAgentTemplate({
    id: 'template-incident-response',
    title: 'SOC Incident Response Playbook',
    description: 'Automated containment, eradication, recovery, and post-incident audit for a reported cyber incident.',
    badge: 'SOC Auto',
    agentId: 'agent-incident',
    agentLabel: 'Incident Response Agent',
    agentSubtitle: 'SOC Playbooks & Containment',
    icon: '🚨',
    inputLabel: 'Incident Title Required',
  }),
  singleAgentTemplate({
    id: 'template-social-engineering',
    title: 'Social Engineering & Deepfake Detection',
    description: 'Detects urgency/impersonation/financial-request manipulation tactics and deepfake media indicators.',
    badge: 'Social Eng',
    agentId: 'agent-social-eng',
    agentLabel: 'Social Engineering / Deepfake Agent',
    agentSubtitle: 'Manipulation Tactic & Media Tamper Check',
    icon: '🎭',
    inputLabel: 'Text / Message / Media Required',
  }),
];

const ORCHESTRATION_AGENTS = [
  { agentId: 'agent-doc-ext', label: 'Certificate Verification', icon: '🤖', y: 20 },
  { agentId: 'agent-identity', label: 'Identity Verification', icon: '🪪', y: 130 },
  { agentId: 'agent-malware', label: 'Malware Analyzer', icon: '🦠', y: 240 },
  { agentId: 'agent-threat', label: 'Threat Detection', icon: '🌐', y: 350 },
  { agentId: 'agent-phishing', label: 'Phishing Detection', icon: '🎣', y: 460 },
  { agentId: 'agent-privacy', label: 'Privacy Compliance', icon: '🔒', y: 570 },
  { agentId: 'agent-password', label: 'Password Advisor', icon: '🔑', y: 680 },
  { agentId: 'agent-fraud', label: 'Fraud Detection', icon: '💳', y: 790 },
  { agentId: 'agent-incident', label: 'Incident Response', icon: '🚨', y: 900 },
  { agentId: 'agent-social-eng', label: 'Social Engineering', icon: '🎭', y: 1010 },
];

const usbTriggerNode = (idSuffix, x, y) => ({
  id: `t-${idSuffix}-trigger`,
  type: 'agentNode',
  position: { x, y },
  data: {
    id: 'trigger-usb-media',
    label: 'Removable Media Trigger',
    subtitle: 'USB Insertion Auto-Trigger',
    icon: '💾',
    isUsbTrigger: true,
    notifyEmail: '',
    credential_id: null,
    armed: true,
    inputLabel: 'Watches for USB Drive Insertion',
    status: 'idle'
  }
});

function buildRemovableMediaGuardianTemplate() {
  const trigger = usbTriggerNode('usb', 60, 260);
  const malware = agentNode('usb-malware', 'agent-malware', 'Malware Analyzer Agent', 'PE & YARA Behavioral Audit', '🦠', 'Auto-Scanned Drive Files', 460, 60);
  const privacy = agentNode('usb-privacy', 'agent-privacy', 'Privacy Compliance Agent', 'GDPR / DPDP PII Audit', '🔒', 'Auto-Scanned Drive Text', 460, 260);
  const incident = agentNode('usb-incident', 'agent-incident', 'Incident Response Agent', 'SOC Playbooks & Containment', '🚨', 'Consolidated Drive Verdict', 460, 460);
  const report = reportNode('usb', 900, 260);

  const nodes = [trigger, malware, privacy, incident, report];
  const edges = [
    edge('e-usb-1', trigger.id, malware.id),
    edge('e-usb-2', trigger.id, privacy.id),
    edge('e-usb-3', malware.id, incident.id),
    edge('e-usb-4', privacy.id, incident.id),
    edge('e-usb-5', incident.id, report.id),
  ];

  return {
    id: 'template-removable-media-guardian',
    title: 'Removable Media Guardian',
    description: 'Arm it, then plug in a USB drive: real-time OS-level insertion detection auto-runs Malware Analysis -> Privacy Compliance -> Incident Response on the drive contents and emails one consolidated report - no click required.',
    badge: 'Auto-Trigger',
    category: 'Automation',
    nodeCount: nodes.length,
    nodes,
    edges,
  };
}

function buildMasterOrchestrationTemplate() {
  const ingest = ingestNode('orch', 60, 500);
  const orchestrator = agentNode('orch', 'agent-decision', 'Master Cyber Orchestrator', 'Multi-Agent Intent Router', '🧠', 'Multi-Agent Synthesis', 420, 500);
  const report = reportNode('orch', 1440, 500);

  const agentNodes = ORCHESTRATION_AGENTS.map((a) =>
    agentNode(`orch-${a.agentId}`, a.agentId, a.label, 'Specialized Agent', a.icon, 'Dispatched by Orchestrator', 900, a.y)
  );

  const nodes = [ingest, orchestrator, ...agentNodes, report];
  const edges = [
    edge('e-orch-in', ingest.id, orchestrator.id),
    ...agentNodes.map((n, i) => edge(`e-orch-fan-${i}`, orchestrator.id, n.id)),
    ...agentNodes.map((n, i) => edge(`e-orch-report-${i}`, n.id, report.id)),
  ];

  return {
    id: 'template-master-orchestration',
    title: 'CyberVerse Complete Multi-Agent Orchestration',
    description: 'The full 11-node pipeline: ingest -> Master Orchestrator -> all 10 specialized agents in parallel -> unified SOC report.',
    badge: 'Enterprise Standard',
    category: 'Orchestration',
    nodeCount: nodes.length,
    nodes,
    edges,
  };
}

// Only this session's actual new work (Removable Media Guardian) is exposed in the
// Templates list. SINGLE_AGENT_TEMPLATES and buildMasterOrchestrationTemplate() above
// are pre-existing, fully-built templates from before this work - left defined but
// unused here rather than deleted, in case they're re-enabled later.
export const WORKFLOW_TEMPLATES = [
  buildRemovableMediaGuardianTemplate(),
];
