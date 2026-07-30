// 3-Agent Multi-Agent Google Drive Verification Template

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

function buildDocumentTrustTemplate() {
  const driveNode = {
    id: 't-gdrive-in',
    type: 'agentNode',
    position: { x: 60, y: 250 },
    data: {
      id: 'node-gdrive-connector',
      label: 'Google Drive Connector',
      subtitle: 'Service Account Folder Importer',
      icon: '📂',
      isTextBox: true,
      inputLabel: 'Google Drive Folder URL',
      status: 'idle'
    }
  };

  const discoveryNode = agentNode('gdrive-disc', 'agent-discovery', 'Document Discovery Service', 'Classification & Preview', '🔍', 'Document Discovery', 420, 250);
  const identityNode = agentNode('gdrive-id', 'agent-identity-spec', 'Identity Verification Specialist', 'Passport, Aadhaar & Biometric Match', '🪪', 'Identity Verification', 800, 100);
  const documentNode = agentNode('gdrive-doc', 'agent-doc-spec', 'Fake Certificate Verification Agent', 'OCR & PKI Forensics', '🤖', 'Document Verification', 800, 400);
  const fraudNode = agentNode('gdrive-fraud', 'agent-fraud-spec', 'Fraud Detection Specialist', 'Cross-Document Anomaly Reasoning', '🛡️', 'Fraud Analysis', 1180, 250);
  const reportNodeObj = reportNode('gdrive-out', 1560, 250);

  const nodes = [driveNode, discoveryNode, identityNode, documentNode, fraudNode, reportNodeObj];
  const edges = [
    edge('e-gd-1', driveNode.id, discoveryNode.id),
    edge('e-gd-2a', discoveryNode.id, identityNode.id),
    edge('e-gd-2b', discoveryNode.id, documentNode.id),
    edge('e-gd-3a', identityNode.id, fraudNode.id),
    edge('e-gd-3b', documentNode.id, fraudNode.id),
    edge('e-gd-4', fraudNode.id, reportNodeObj.id),
  ];

  return {
    id: 'template-document-trust',
    title: 'AI Document Trust & Verification Workflow',
    description: 'Enterprise 3-agent Google Drive document trust and verification workflow with parallel agent execution and MongoDB Compass storage.',
    badge: '3-Agent Multi-Agent',
    category: 'Verification',
    nodeCount: nodes.length,
    nodes,
    edges,
  };
}

export const WORKFLOW_TEMPLATES = [
  buildDocumentTrustTemplate(),
];
