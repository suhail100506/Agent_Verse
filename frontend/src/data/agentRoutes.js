// Maps a node's data.id (the agent identity, not the React Flow node id) to the backend
// endpoint that executes it. `kind: 'file'` sends the payload as a Blob under `field`;
// `kind: 'text'` sends it as a plain form field. `fileMime`/`fileName` are used when the
// user typed text instead of uploading a file, so we can still satisfy a file-shaped endpoint.
export const AGENT_ROUTES = {
  'agent-doc-ext': { url: '/api/verify/certificate', field: 'file', kind: 'file', fileMime: 'text/plain', fileName: 'test_certificate.txt' },
  'agent-auth-ver': { url: '/api/verify/certificate', field: 'file', kind: 'file', fileMime: 'text/plain', fileName: 'test_certificate.txt' },
  'agent-vis-forensics': { url: '/api/verify/certificate', field: 'file', kind: 'file', fileMime: 'text/plain', fileName: 'test_certificate.txt' },
  'agent-decision': { url: '/api/orchestrator/analyze', field: 'prompt', kind: 'text' },
  'agent-identity': { url: '/api/verify/identity', field: 'document_file', kind: 'file', fileMime: 'text/plain', fileName: 'id_document.txt' },
  'agent-malware': { url: '/api/analyze/malware', field: 'file', kind: 'file', fileMime: 'application/octet-stream', fileName: 'suspicious.exe' },
  'agent-threat': { url: '/api/analyze/threat', field: 'query', kind: 'text' },
  'agent-phishing': { url: '/api/analyze/phishing', field: 'url_or_text', kind: 'text' },
  'agent-privacy': { url: '/api/audit/privacy', field: 'text_content', kind: 'text' },
  'agent-password': { url: '/api/advise/password', field: 'password', kind: 'text' },
  'agent-fraud': { url: '/api/detect/fraud', field: 'location', kind: 'text' },
  'agent-incident': { url: '/api/incident/respond', field: 'payload', kind: 'text' },
  'agent-social-eng': { url: '/api/analyze/social-engineering', field: 'text', kind: 'text' },
};

export const DEFAULT_ROUTE = { url: '/api/analyze/phishing', field: 'url_or_text', kind: 'text' };

// Shared by AgentNode's single-node "Run Node" button and the full-graph executor,
// so credential/prompt/model/notify-email/agent-specific field wiring only lives once.
export function buildAgentFormData(route, targetData, val, fileVal) {
  const formData = new FormData();

  if (route.kind === 'file') {
    if (fileVal) {
      formData.append(route.field, fileVal);
    } else {
      const blob = new Blob([val || ''], { type: route.fileMime || 'text/plain' });
      formData.append(route.field, blob, route.fileName || 'payload.txt');
    }
  } else {
    formData.append(route.field, val || fileVal?.name || targetData?.targetUrl || '');
  }

  if (targetData?.credential_id) formData.append('credential_id', targetData.credential_id);
  if (targetData?.systemPrompt) formData.append('system_prompt', targetData.systemPrompt);
  if (targetData?.model) formData.append('model', targetData.model);
  if (targetData?.notifyEmail) formData.append('notify_email', targetData.notifyEmail);
  if (targetData?.defaultAmount) formData.append('amount', targetData.defaultAmount);
  if (targetData?.severity) formData.append('severity', targetData.severity);

  return formData;
}
