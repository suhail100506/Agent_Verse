import { AGENT_ROUTES } from './agentRoutes';

// Classifies a node so NodePopup can render ONLY the settings relevant to that
// node, instead of one generic panel shared by every node type.
export function getNodeKind(data) {
  if (!data) return 'generic';
  if (data.isTextBox) return 'trigger-text';
  if (data.isWebhookTrigger) return 'trigger-webhook';
  if (data.cron !== undefined) return 'trigger-schedule';
  if (data.isLogicNode) return 'logic';
  if (data.id === 'node-final-report') return 'report';
  if (data.id && AGENT_ROUTES[data.id]) return 'agent';
  return 'generic';
}

// Extra fields specific to individual agents, layered on top of the fields every
// 'agent' kind node gets (System Prompt / Model / Notify Email / Credentials tab).
// These are real - their values are sent to the backend and change what that
// agent actually does, not just cosmetic.
export const AGENT_EXTRA_FIELDS = {
  'agent-fraud': [
    { key: 'defaultAmount', label: 'Transaction Amount ($)', type: 'number', placeholder: '2500' },
  ],
  'agent-incident': [
    { key: 'severity', label: 'Incident Severity', type: 'select', options: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'EMERGENCY'], default: 'HIGH' },
  ],
};
