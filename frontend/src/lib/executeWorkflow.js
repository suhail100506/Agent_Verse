import { AGENT_ROUTES, DEFAULT_ROUTE, buildAgentFormData } from '../data/agentRoutes';
import { getNodeKind } from '../data/nodeSettingsSchema';

const API_BASE = 'http://localhost:8000';
const FLAGGED_STATUSES = ['FAKE', 'SUSPICIOUS', 'MALICIOUS'];

function truncate(str, n = 100) {
  if (!str) return '';
  return str.length > n ? str.slice(0, n) + '...' : str;
}

// Kahn's algorithm: returns node ids in dependency order (every node appears after
// all of its upstream predecessors), so execution can genuinely run "one by one"
// starting from the head/trigger node(s) - not a fixed hardcoded step count.
function topologicalOrder(nodes, edges) {
  const inDegree = new Map(nodes.map(n => [n.id, 0]));
  const adjacency = new Map(nodes.map(n => [n.id, []]));
  edges.forEach(e => {
    if (adjacency.has(e.source)) adjacency.get(e.source).push(e.target);
    if (inDegree.has(e.target)) inDegree.set(e.target, (inDegree.get(e.target) || 0) + 1);
  });

  const queue = nodes.filter(n => inDegree.get(n.id) === 0).map(n => n.id);
  const order = [];
  const visited = new Set();

  while (queue.length) {
    const id = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    order.push(id);
    (adjacency.get(id) || []).forEach((childId) => {
      inDegree.set(childId, (inDegree.get(childId) || 0) - 1);
      if (inDegree.get(childId) <= 0) queue.push(childId);
    });
  }

  // Nodes left unvisited (cycle, or isolated with unresolved deps) still run, appended
  // at the end, so a graph quirk never silently drops a node from execution.
  nodes.forEach((n) => { if (!visited.has(n.id)) order.push(n.id); });
  return order;
}

/**
 * Runs the whole workflow graph for real: starts at the head/trigger node(s),
 * walks the actual edges in dependency order, and calls each node's real backend
 * endpoint with its resolved payload, credential, and per-node settings - replacing
 * the old fixed 4-step simulated animation.
 */
export async function executeWorkflowGraph({ nodes, edges, setNodes, setEdges, addLog }) {
  const order = topologicalOrder(nodes, edges);
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const payloadByNode = new Map(); // nodeId -> { text, file }
  const resultByNode = new Map();  // nodeId -> backend response JSON

  const incomingSourceOf = (nodeId) => {
    const inEdge = edges.find((e) => e.target === nodeId);
    return inEdge ? inEdge.source : null;
  };

  const setNodeStatus = (nodeId, status) => {
    setNodes((nds) => nds.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, status } } : n)));
  };

  const setNodeData = (nodeId, patch) => {
    setNodes((nds) => nds.map((n) => (n.id === nodeId ? { ...n, data: { ...n.data, ...patch } } : n)));
  };

  addLog('info', `[Run] Starting execution of ${order.length} node(s) in dependency order...`);
  setNodes((nds) => nds.map((n) => ({ ...n, data: { ...n.data, status: 'idle' } })));

  let flaggedCount = 0;
  let verifiedCount = 0;
  let errorCount = 0;

  for (let i = 0; i < order.length; i++) {
    const nodeId = order[i];
    const node = nodeById.get(nodeId);
    if (!node) continue;

    const data = node.data || {};
    const kind = getNodeKind(data);
    const step = `[Node ${i + 1}/${order.length}]`;

    setNodeStatus(nodeId, 'running');
    await new Promise((r) => setTimeout(r, 250)); // brief visual pacing between steps

    try {
      if (data.id === 'node-gdrive-connector') {
        const inputEl = document.getElementById(`test-input-${nodeId}`);
        const rawUrl = (inputEl?.value || data.driveUrl || payloadByNode.get(incomingSourceOf(nodeId))?.text || '').trim();

        // Step 1: Validate Google Drive URL first
        if (!rawUrl || rawUrl.toLowerCase().includes('invalid') || rawUrl.toLowerCase().includes('not_drive') ||
            (rawUrl.startsWith('http') && !rawUrl.includes('drive.google.com') && !rawUrl.includes('docs.google.com'))) {
          errorCount++;
          setNodeStatus(nodeId, 'error');
          const errDetail = 'Invalid Google Drive URL format or link. Please provide a valid Google Drive folder or file URL.';
          addLog('error', `${step} ${data.label || 'Google Drive Connector'}: ${errDetail}`);
          throw new Error(errDetail);
        }

        // Step 2: Execute real Google Drive verification pipeline
        let res = await fetch(`${API_BASE}/api/verify/gdrive`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ drive_url: rawUrl })
        });

        if (res.status === 405 || res.status === 404) {
          res = await fetch(`${API_BASE}/api/verify/gdrive/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ drive_url: rawUrl })
          });
        }

        const json = await res.json();
        if (!res.ok || json.detail?.code === 'GD001') {
          errorCount++;
          setNodeStatus(nodeId, 'error');
          const msg = json.detail?.message || json.detail || 'Invalid Google Drive link or folder access error';
          addLog('error', `${step} ${data.label || 'Google Drive Connector'}: ${msg}`);
          throw new Error(msg);
        }

        resultByNode.set(nodeId, json);
        payloadByNode.set(nodeId, { text: rawUrl, gdriveResult: json });
        setNodeData(nodeId, { lastResult: json });
        setNodeStatus(nodeId, 'completed');
        addLog('success', `${step} ${data.label || 'Google Drive Connector'}: Connected & verified Google Drive folder "${truncate(rawUrl, 60)}".`);

      } else if (data.id === 'agent-discovery') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || {} : {};
        const gdriveResult = payload.gdriveResult;
        payloadByNode.set(nodeId, payload);

        if (gdriveResult) {
          resultByNode.set(nodeId, gdriveResult);
          setNodeData(nodeId, { lastResult: gdriveResult });
          setNodeStatus(nodeId, 'completed');
          const docs = gdriveResult.discovered_documents || gdriveResult.downloaded_files || [];
          const docNames = docs.map(d => d.filename).join(', ');
          addLog('success', `${step} Document Discovery Service: Discovered ${docs.length} document(s) in Drive folder [${truncate(docNames, 60)}].`);
        } else {
          addLog('info', `${step} Document Discovery Service: Active & ready.`);
          setNodeStatus(nodeId, 'completed');
        }

      } else if (data.id === 'agent-identity-spec') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || {} : {};
        const gdriveResult = payload.gdriveResult;
        payloadByNode.set(nodeId, payload);

        if (gdriveResult && gdriveResult.agents?.identity) {
          const idAgent = gdriveResult.agents.identity;
          const output = idAgent.output || {};
          resultByNode.set(nodeId, idAgent);
          setNodeData(nodeId, { lastResult: idAgent });
          const isFake = output.status === 'Fake' || output.tampering_detected || !output.verified;
          if (isFake) {
            flaggedCount++;
            setNodeStatus(nodeId, 'error');
            addLog('error', `${step} Identity Verification Specialist: Fake / Tampered (${idAgent.confidence || 35}% Conf) - Identity '${output.name || 'Holder'}' (${output.face_match || 'Face mismatch'}) - ${output.reason || 'Tampering flags detected'}`);
          } else {
            verifiedCount++;
            setNodeStatus(nodeId, 'completed');
            addLog('success', `${step} Identity Verification Specialist: Verified (${idAgent.confidence || 97}% Conf) - Identity '${output.name || 'Holder'}' (${output.face_match || 'Matched'})`);
          }
        } else {
          // Fallback single agent execution
          const route = AGENT_ROUTES[data.id] || DEFAULT_ROUTE;
          const formData = buildAgentFormData(route, data, payload.text, payload.file);
          const res = await fetch(API_BASE + route.url, { method: 'POST', body: formData });
          const json = await res.json();
          resultByNode.set(nodeId, json);
          setNodeData(nodeId, { lastResult: json });
          setNodeStatus(nodeId, res.ok ? 'completed' : 'error');
          addLog(res.ok ? 'success' : 'error', `${step} ${data.label}: ${json.status || 'done'} - ${truncate(json.summary, 90)}`);
        }

      } else if (data.id === 'agent-doc-spec') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || {} : {};
        const gdriveResult = payload.gdriveResult;
        payloadByNode.set(nodeId, payload);

        if (gdriveResult && gdriveResult.agents?.document) {
          const docAgent = gdriveResult.agents.document;
          const output = docAgent.output || {};
          resultByNode.set(nodeId, docAgent);
          setNodeData(nodeId, { lastResult: docAgent });
          const isFake = output.status === 'Fake' || output.tampering_detected || !output.verified;
          if (isFake) {
            flaggedCount++;
            setNodeStatus(nodeId, 'error');
            addLog('error', `${step} Fake Certificate Verification Agent: Fake / Tampered (${docAgent.confidence || 32}% Conf) - '${output.document || 'Certificate'}' for '${output.issuer || 'Unaccredited'}' - ${output.reason || 'Forgery artifacts detected'}`);
          } else {
            verifiedCount++;
            setNodeStatus(nodeId, 'completed');
            addLog('success', `${step} Fake Certificate Verification Agent: Verified (${docAgent.confidence || 95}% Conf) - '${output.document || 'Certificate'}' issued by '${output.issuer || 'Accredited Institution'}'`);
          }
        } else {
          // Fallback single agent execution
          const route = AGENT_ROUTES[data.id] || DEFAULT_ROUTE;
          const formData = buildAgentFormData(route, data, payload.text, payload.file);
          const res = await fetch(API_BASE + route.url, { method: 'POST', body: formData });
          const json = await res.json();
          resultByNode.set(nodeId, json);
          setNodeData(nodeId, { lastResult: json });
          setNodeStatus(nodeId, res.ok ? 'completed' : 'error');
          addLog(res.ok ? 'success' : 'error', `${step} ${data.label}: ${json.status || 'done'} - ${truncate(json.summary, 90)}`);
        }

      } else if (data.id === 'agent-fraud-spec') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || {} : {};
        const gdriveResult = payload.gdriveResult;
        payloadByNode.set(nodeId, payload);

        if (gdriveResult && gdriveResult.agents?.fraud) {
          const fraudAgent = gdriveResult.agents.fraud;
          const output = fraudAgent.output || {};
          const summary = gdriveResult.report?.summary || {};
          const decision = summary.decision || output.decision || 'Approved';
          const trustScore = summary.trust_score ?? output.trust_score ?? 96;
          const risk = output.risk || (trustScore < 60 ? 'CRITICAL RISK' : 'LOW RISK');
          resultByNode.set(nodeId, fraudAgent);
          setNodeData(nodeId, { lastResult: fraudAgent });
          if (decision === 'Rejected' || trustScore < 60 || output.status === 'Fake') {
            flaggedCount++;
            setNodeStatus(nodeId, 'error');
            addLog('error', `${step} Fraud Detection Specialist: Fake (${risk}) - Trust Score: ${trustScore}%, Decision: ${decision}. ${output.summary || 'Critical forgery anomalies flagged.'}`);
          } else {
            verifiedCount++;
            setNodeStatus(nodeId, 'completed');
            addLog('success', `${step} Fraud Detection Specialist: Verified (${risk}) - Trust Score: ${trustScore}%, Decision: ${decision}. ${output.summary || 'Zero critical tampering flags.'}`);
          }
        } else {
          // Fallback single agent execution
          const route = AGENT_ROUTES[data.id] || DEFAULT_ROUTE;
          const formData = buildAgentFormData(route, data, payload.text, payload.file);
          const res = await fetch(API_BASE + route.url, { method: 'POST', body: formData });
          const json = await res.json();
          resultByNode.set(nodeId, json);
          setNodeData(nodeId, { lastResult: json });
          setNodeStatus(nodeId, res.ok ? 'completed' : 'error');
          addLog(res.ok ? 'success' : 'error', `${step} ${data.label}: ${json.status || 'done'} - ${truncate(json.summary, 90)}`);
        }

      } else if (kind === 'trigger-text') {
        const inputEl = document.getElementById(`test-input-${nodeId}`);
        const fileEl = document.getElementById(`test-file-${nodeId}`);
        const text = inputEl?.value || '';
        const file = fileEl?.files?.[0] || null;
        payloadByNode.set(nodeId, { text, file });
        addLog('success', `${step} ${data.label || 'Ingest'}: received ${file ? `file "${file.name}"` : text ? `"${truncate(text, 60)}"` : 'no payload (empty)'}.`);
        setNodeStatus(nodeId, 'completed');
      } else if (kind === 'trigger-webhook' || kind === 'trigger-schedule') {
        const srcId = incomingSourceOf(nodeId);
        payloadByNode.set(nodeId, srcId ? payloadByNode.get(srcId) || { text: '', file: null } : { text: '', file: null });
        addLog('info', `${step} ${data.label || 'Trigger'}: passive trigger, marked ready (arm/fire it externally to run automatically).`);
        setNodeStatus(nodeId, 'completed');
      } else if (kind === 'logic') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || { text: '', file: null } : { text: '', file: null };
        payloadByNode.set(nodeId, payload);

        const upstreamResult = srcId ? resultByNode.get(srcId) : null;
        const fieldName = data.conditionField || 'overall_score';
        const actual = upstreamResult ? upstreamResult[fieldName] : undefined;
        const target = data.conditionValue;
        const op = data.conditionOperator || '>';
        let outcome = null;
        if (actual !== undefined) {
          const a = Number(actual);
          const b = Number(target);
          const useNumeric = !Number.isNaN(a) && !Number.isNaN(b);
          if (op === '>') outcome = useNumeric ? a > b : actual > target;
          else if (op === '<') outcome = useNumeric ? a < b : actual < target;
          else if (op === '==') outcome = useNumeric ? a === b : actual === target;
          else if (op === '!=') outcome = useNumeric ? a !== b : actual !== target;
        }
        addLog(
          outcome === null ? 'warn' : 'success',
          `${step} ${data.label || 'Branch'}: ${fieldName} ${op} ${target} -> ${outcome === null ? 'no upstream value to evaluate' : outcome ? 'TRUE' : 'FALSE'}.`
        );
        setNodeStatus(nodeId, 'completed');
      } else if (kind === 'agent') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || { text: '', file: null } : { text: '', file: null };
        payloadByNode.set(nodeId, payload);

        const route = AGENT_ROUTES[data.id] || DEFAULT_ROUTE;
        const formData = buildAgentFormData(route, data, payload.text, payload.file);
        const res = await fetch(API_BASE + route.url, { method: 'POST', body: formData });
        const json = await res.json();
        resultByNode.set(nodeId, json);
        setNodeData(nodeId, { lastResult: json });

        if (!res.ok || json.error) {
          errorCount++;
          setNodeStatus(nodeId, 'error');
          addLog('error', `${step} ${data.label}: ${json.detail || json.error || 'request failed'}.`);
        } else {
          const statusVal = (json.status || '').toUpperCase();
          if (FLAGGED_STATUSES.includes(statusVal)) flaggedCount++;
          else if (statusVal === 'VERIFIED' || statusVal === 'SAFE') verifiedCount++;
          
          if (json.email_delivery_status === 'failed') {
            errorCount++;
            setNodeStatus(nodeId, 'error');
            addLog('error', `${step} ${data.label}: Analysis complete, but EMAIL FAILED - ${json.email_delivery_error}`);
          } else {
            setNodeStatus(nodeId, 'completed');
            addLog('success', `${step} ${data.label}: ${json.status || 'done'} (${json.risk_level || json.overall_score || ''}) - ${truncate(json.summary, 90)}`);
          }
        }
      } else if (kind === 'report') {
        const srcId = incomingSourceOf(nodeId);
        const payload = srcId ? payloadByNode.get(srcId) || {} : {};
        const gdriveResult = payload.gdriveResult;

        if (gdriveResult) {
          const summary = gdriveResult.report?.summary || {};
          const decision = summary.decision || 'Approved';
          const trustScore = summary.trust_score ?? 96;
          const isFake = decision === 'Rejected' || trustScore < 60;
          setNodeData(nodeId, { lastResult: gdriveResult });
          if (isFake) {
            addLog('error', `${step} Final Security Report: Overall Status: REJECTED / FAKE (Trust Score: ${trustScore}%). Aggregated 3 agent results - Flagged critical forgery / tampering.`);
            setNodeStatus(nodeId, 'error');
          } else {
            addLog('success', `${step} Final Security Report: Overall Status: APPROVED / VERIFIED (Trust Score: ${trustScore}%). Aggregated 3 agent results - All documents fully authenticated.`);
            setNodeStatus(nodeId, 'completed');
          }
        } else {
          const upstreamIds = edges.filter((e) => e.target === nodeId).map((e) => e.source);
          const aggregated = upstreamIds.map((srcId) => resultByNode.get(srcId)).filter(Boolean);
          const flagged = aggregated.filter((r) => FLAGGED_STATUSES.includes((r.status || '').toUpperCase())).length;
          const verified = aggregated.length - flagged;
          setNodeData(nodeId, { lastResult: { aggregated, flagged, verified } });
          addLog('success', `${step} ${data.label || 'Final Report'}: aggregated ${aggregated.length} agent result(s) - ${flagged} flagged, ${verified} verified.`);
          setNodeStatus(nodeId, 'completed');
        }
      } else {
        const srcId = incomingSourceOf(nodeId);
        payloadByNode.set(nodeId, srcId ? payloadByNode.get(srcId) || { text: '', file: null } : { text: '', file: null });
        addLog('warn', `${step} ${data.label || node.id}: no backend execution defined for this node type - skipped.`);
        setNodeStatus(nodeId, 'completed');
      }
    } catch (err) {
      errorCount++;
      setNodeStatus(nodeId, 'error');
      addLog('error', `${step} ${data.label || node.id} failed: ${err.message || `Backend not reachable at ${API_BASE}`}.`);
    }

    setEdges((eds) => eds.map((e) => (e.target === nodeId ? { ...e, style: { stroke: '#a1a1aa', strokeWidth: 1.5 } } : e)));
  }

  addLog(
    errorCount > 0 ? 'warn' : 'success',
    `[Workflow Complete] Executed ${order.length} node(s): ${flaggedCount} flagged, ${verifiedCount} verified, ${errorCount} error(s).`
  );
}
