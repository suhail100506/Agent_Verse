import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  useNodesState,
  useEdgesState,
  ReactFlowProvider
} from '@xyflow/react';

import Header from './Header';
import Sidebar from './Sidebar';
import WorkflowCanvas from './WorkflowCanvas';
import NodePopup from './NodePopup';
import BottomConsole from './BottomConsole';
import CommandPalette from './CommandPalette';
import AiCopilotModal from './AiCopilotModal';
import TemplatesModal from './TemplatesModal';
import { WORKFLOW_TEMPLATES } from '../data/templates';
import { executeWorkflowGraph } from '../lib/executeWorkflow';

const INITIAL_NODES = [
  {
    id: 'node-trigger-ingest',
    type: 'agentNode',
    position: { x: 80, y: 150 },
    data: {
      id: 'node-user-upload',
      label: 'User Payload Ingest',
      subtitle: 'Payload Trigger Input',
      icon: '📄',
      isTextBox: true,
      inputLabel: 'User Payload',
      status: 'idle'
    }
  },
  {
    id: 'node-orchestrator',
    type: 'agentNode',
    position: { x: 420, y: 150 },
    data: {
      id: 'agent-decision',
      label: 'Master Cyber Orchestrator',
      subtitle: 'Multi-Agent Intent Router',
      icon: '🧠',
      inputLabel: 'Multi-Agent Synthesis',
      status: 'idle'
    }
  },
  {
    id: 'node-doc-forensics',
    type: 'agentNode',
    position: { x: 780, y: 50 },
    data: {
      id: 'agent-doc-ext',
      label: 'Document Extraction Agent',
      subtitle: 'OCR & Layout Metadata',
      icon: '🤖',
      inputLabel: 'PDF Document Required',
      status: 'idle'
    }
  },
  {
    id: 'node-malware-scan',
    type: 'agentNode',
    position: { x: 780, y: 250 },
    data: {
      id: 'agent-malware',
      label: 'Malware Analyzer Agent',
      subtitle: 'PE & YARA Behavioral Audit',
      icon: '🦠',
      inputLabel: 'Binary Executable (.exe)',
      status: 'idle'
    }
  },
  {
    id: 'node-report',
    type: 'agentNode',
    position: { x: 1140, y: 150 },
    data: {
      id: 'node-final-report',
      label: 'Final Security Report',
      subtitle: 'JSON & PDF SOC Exporter',
      icon: '📋',
      inputLabel: 'Report Generator',
      status: 'idle'
    }
  }
];

const INITIAL_EDGES = [
  { id: 'edge-1-2', source: 'node-trigger-ingest', target: 'node-orchestrator', animated: true, style: { stroke: '#6366f1', strokeWidth: 2.5 } },
  { id: 'edge-2-3', source: 'node-orchestrator', target: 'node-doc-forensics', animated: true, style: { stroke: '#06b6d4', strokeWidth: 2 } },
  { id: 'edge-2-4', source: 'node-orchestrator', target: 'node-malware-scan', animated: true, style: { stroke: '#06b6d4', strokeWidth: 2 } },
  { id: 'edge-3-5', source: 'node-doc-forensics', target: 'node-report', animated: true, style: { stroke: '#10b981', strokeWidth: 2 } },
  { id: 'edge-4-5', source: 'node-malware-scan', target: 'node-report', animated: true, style: { stroke: '#10b981', strokeWidth: 2 } }
];

// Persists the canvas (nodes/edges - including per-node config like Notify Email,
// bound credentials, and system prompt overrides) to localStorage, so a browser
// refresh restores exactly what was on the canvas instead of resetting to the
// default starter graph.
const CANVAS_STORAGE_KEY = 'cyberverse.canvas.v1';

function loadPersistedCanvas() {
  try {
    const raw = localStorage.getItem(CANVAS_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed?.nodes) || parsed.nodes.length === 0) return null;
    // Reset transient execution state (running/error spinners, stale USB status text)
    // on load - only the node's actual configuration needs to survive a refresh.
    const nodes = parsed.nodes.map((n) => ({ ...n, data: { ...n.data, status: 'idle', usbStatusText: undefined } }));
    return { nodes, edges: Array.isArray(parsed.edges) ? parsed.edges : [] };
  } catch {
    return null;
  }
}

function WorkflowBuilderContent() {
  const persistedCanvas = loadPersistedCanvas(); // only the initial value matters - read once per mount
  const [nodes, setNodes, onNodesChange] = useNodesState(persistedCanvas?.nodes || INITIAL_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(persistedCanvas?.edges || INITIAL_EDGES);

  // Save the canvas back to localStorage on every change (node config edits, drags,
  // template loads, new connections) so it survives a refresh.
  useEffect(() => {
    try {
      localStorage.setItem(CANVAS_STORAGE_KEY, JSON.stringify({ nodes, edges }));
    } catch {
      // localStorage unavailable/full - silently skip persistence, canvas still works in-memory
    }
  }, [nodes, edges]);

  const [selection, setSelection] = useState({ node: null, anchor: null });
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isConsoleOpen, setIsConsoleOpen] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [isSaved, setIsSaved] = useState(true);

  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isAiCopilotOpen, setIsAiCopilotOpen] = useState(false);
  const [isTemplatesOpen, setIsTemplatesOpen] = useState(false);

  const [logs, setLogs] = useState([
    { id: 1, type: 'info', timestamp: new Date().toLocaleTimeString(), message: '[CyberVerse Engine] Ready for multi-agent execution.' }
  ]);

  const addLog = useCallback((type, message) => {
    setLogs(prev => [
      ...prev,
      { id: Date.now(), type, timestamp: new Date().toLocaleTimeString(), message }
    ]);
  }, []);

  // Register any webhook-trigger node's downstream agent with the backend so
  // POST /api/triggers/webhook/{node_id} can be fired externally (v1: in-memory only).
  useEffect(() => {
    nodes.forEach((n) => {
      if (!n.data?.isWebhookTrigger) return;
      const outEdge = edges.find(e => e.source === n.id);
      const targetNode = outEdge ? nodes.find(nn => nn.id === outEdge.target) : null;
      if (!targetNode?.data?.id) return;

      const formData = new FormData();
      formData.append('node_id', n.id);
      formData.append('agent_id', targetNode.data.id);
      fetch('http://localhost:8000/api/triggers/register', { method: 'POST', body: formData }).catch(() => {});
    });
  }, [nodes, edges]);

  // Removable Media Guardian: whenever a USB-trigger node is on canvas, arm the real
  // backend watcher (ctypes-based removable-drive polling - see usb_guardian.py) with
  // this node's Notify Email / bound SMTP credential.
  const usbTriggerNode = nodes.find((n) => n.data?.isUsbTrigger) || null;
  const usbNodeId = usbTriggerNode?.id || null;
  const usbNotifyEmail = usbTriggerNode?.data?.notifyEmail || '';
  const usbCredentialId = usbTriggerNode?.data?.credential_id || '';
  const usbArmedFlag = usbTriggerNode?.data?.armed;
  const usbPrevStageRef = useRef(null);

  useEffect(() => {
    if (!usbNodeId || usbArmedFlag === false) return;
    const formData = new FormData();
    formData.append('node_id', usbNodeId);
    if (usbNotifyEmail) formData.append('notify_email', usbNotifyEmail);
    if (usbCredentialId) formData.append('credential_id', usbCredentialId);
    fetch('http://localhost:8000/api/triggers/usb/arm', { method: 'POST', body: formData }).catch(() => {});
  }, [usbNodeId, usbNotifyEmail, usbCredentialId, usbArmedFlag]);

  // Poll the real backend pipeline status (~1.5s) and mirror each stage transition onto
  // the matching canvas nodes - this is what makes plugging in a real USB drive animate
  // the workflow with zero clicks, instead of only the manual "Run Workflow" button path.
  useEffect(() => {
    if (!usbNodeId) {
      usbPrevStageRef.current = null;
      return;
    }

    const setAgentStatus = (agentId, status, lastResult) => {
      setNodes((nds) => nds.map((n) => (
        n.data?.id === agentId ? { ...n, data: { ...n.data, status, ...(lastResult !== undefined ? { lastResult } : {}) } } : n
      )));
    };

    const setUsbStatusText = (text) => {
      setNodes((nds) => nds.map((n) => (n.id === usbNodeId ? { ...n, data: { ...n.data, usbStatusText: text } } : n)));
    };

    const STATUS_LABELS = {
      idle: 'Not armed yet.',
      watching: 'Armed - watching for USB drive insertion...',
      scanning: 'Drive detected - scanning files...',
      malware: 'Running Malware Analyzer on drive contents...',
      privacy: 'Running Privacy Compliance audit on drive text...',
      incident: 'Running Incident Response playbook...',
      emailing: 'Compiling consolidated report & sending email...',
      completed: 'Pipeline complete - report emailed.',
      error: 'Pipeline failed - see console.',
    };

    const poll = async () => {
      let status;
      try {
        const res = await fetch('http://localhost:8000/api/triggers/usb/status');
        status = await res.json();
      } catch {
        return; // backend unreachable this tick - next poll retries
      }

      setUsbStatusText(
        status.status === 'scanning' && status.drive
          ? `Drive ${status.drive} detected - scanning files...`
          : (STATUS_LABELS[status.status] || status.status)
      );

      if (status.status === usbPrevStageRef.current) return; // only act on real stage transitions
      const prevStage = usbPrevStageRef.current;
      usbPrevStageRef.current = status.status;

      if (status.status === 'watching' && prevStage !== null) {
        addLog('info', '[USB Guardian] Armed - watching for a removable drive insertion...');
      } else if (status.status === 'scanning') {
        ['agent-malware', 'agent-privacy', 'agent-incident', 'node-final-report'].forEach((aid) => setAgentStatus(aid, 'idle'));
        addLog('success', `[USB Guardian] Drive ${status.drive} inserted - scanning ${status.files_found?.length ?? '...'} file(s).`);
      } else if (status.status === 'malware') {
        setAgentStatus('agent-malware', 'running');
        addLog('info', `[USB Guardian] Found ${status.files_found?.length || 0} file(s). Running Malware Analyzer...`);
      } else if (status.status === 'privacy') {
        setAgentStatus('agent-malware', 'completed', status.results?.malware?.[0]);
        setAgentStatus('agent-privacy', 'running');
        addLog('success', `[USB Guardian] Malware Analyzer: ${status.results?.malware?.[0]?.status || 'done'}. Running Privacy Compliance...`);
      } else if (status.status === 'incident') {
        setAgentStatus('agent-privacy', 'completed', status.results?.privacy);
        setAgentStatus('agent-incident', 'running');
        addLog('success', `[USB Guardian] Privacy audit: ${status.results?.privacy?.status || 'done'}. Running Incident Response...`);
      } else if (status.status === 'emailing') {
        setAgentStatus('agent-incident', 'completed', status.results?.incident);
        setAgentStatus('node-final-report', 'running');
        addLog('success', '[USB Guardian] Incident Response complete. Compiling report & sending email...');
      } else if (status.status === 'completed') {
        setAgentStatus('node-final-report', 'completed', status.final_report);
        const emailStatus = status.final_report?.email_delivery_status;
        const emailNote = emailStatus === 'success'
          ? 'Email sent.'
          : `Email ${emailStatus || 'not sent'}${status.final_report?.email_delivery_error ? ` - ${status.final_report.email_delivery_error}` : ''}.`;
        addLog('success', `[USB Guardian] Workflow complete: ${status.final_report?.status || 'done'}. ${emailNote}`);
      } else if (status.status === 'error') {
        addLog('error', `[USB Guardian] Pipeline failed: ${status.error}`);
      }
    };

    poll();
    const interval = setInterval(poll, 1500);
    return () => clearInterval(interval);
  }, [usbNodeId, setNodes, addLog]);

  // Update selected node data
  const handleUpdateNode = useCallback((nodeId, updatedData) => {
    setIsSaved(false);
    setNodes(nds => nds.map(n => {
      if (n.id === nodeId) {
        const nextNode = { ...n, data: { ...n.data, ...updatedData } };
        setSelection(sel => (sel.node && sel.node.id === nodeId) ? { ...sel, node: nextNode } : sel);
        return nextNode;
      }
      return n;
    }));
  }, [setNodes]);

  // Delete node
  const handleDeleteNode = useCallback((nodeId) => {
    setIsSaved(false);
    setNodes(nds => nds.filter(n => n.id !== nodeId));
    setEdges(eds => eds.filter(e => e.source !== nodeId && e.target !== nodeId));
    setSelection({ node: null, anchor: null });
    addLog('warn', `Removed node ${nodeId} from canvas.`);
  }, [setNodes, setEdges, addLog]);

  const handleNodeSelect = useCallback((node, anchor) => {
    setSelection({ node, anchor });
  }, []);

  // Real dynamic execution: walks the actual graph from its head/trigger node(s)
  // through every downstream node in dependency order, calling each node's real
  // backend endpoint - not a fixed simulated step count.
  const handleRunWorkflow = useCallback(async () => {
    if (nodes.length === 0) {
      addLog('warn', 'Nothing to run - add some nodes to the canvas first.');
      return;
    }
    setIsRunning(true);
    setIsConsoleOpen(true);
    try {
      await executeWorkflowGraph({ nodes, edges, setNodes, setEdges, addLog });
    } finally {
      setIsRunning(false);
    }
  }, [nodes, edges, setNodes, setEdges, addLog]);

  // Load preset template - each entry in WORKFLOW_TEMPLATES carries its own real {nodes, edges} graph
  const handleLoadTemplate = useCallback((templateId) => {
    setIsSaved(false);
    const tmpl = WORKFLOW_TEMPLATES.find(t => t.id === templateId);
    if (!tmpl) {
      setNodes(INITIAL_NODES);
      setEdges(INITIAL_EDGES);
      addLog('warn', `Unknown template "${templateId}" - loaded default SOC pipeline instead.`);
      return;
    }
    // Deep-clone so repeated loads of the same template don't share node/edge object references
    setNodes(JSON.parse(JSON.stringify(tmpl.nodes)));
    setEdges(JSON.parse(JSON.stringify(tmpl.edges)));
    addLog('info', `Loaded template: ${tmpl.title}`);
  }, [setNodes, setEdges, addLog]);

  // Generate AI Workflow
  const handleGenerateAiWorkflow = useCallback((promptText) => {
    setIsSaved(false);
    addLog('info', `[AI Copilot] Generating flow graph for prompt: "${promptText.substring(0, 40)}..."`);
    handleLoadTemplate('template-certificate-verification');
  }, [handleLoadTemplate, addLog]);

  // Add node from Command Palette
  const handleAddNodeFromPalette = useCallback((defaultData) => {
    setIsSaved(false);
    const newNode = {
      id: `node-${Date.now()}`,
      type: 'agentNode',
      position: { x: 400 + Math.random() * 100, y: 200 + Math.random() * 100 },
      data: { ...defaultData, status: 'idle' }
    };
    setNodes(nds => nds.concat(newNode));
    addLog('info', `Added new ${defaultData.label} node to canvas.`);
  }, [setNodes, addLog]);

  return (
    <div className="w-full h-screen flex flex-col bg-[#0b0f14] text-slate-100 overflow-hidden select-none">
      {/* TOP NAVIGATION HEADER */}
      <Header 
        onRunWorkflow={handleRunWorkflow}
        isRunning={isRunning}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenAiCopilot={() => setIsAiCopilotOpen(true)}
        onOpenTemplates={() => setIsTemplatesOpen(true)}
        onSaveWorkflow={() => setIsSaved(true)}
        isSaved={isSaved}
        nodeCount={nodes.length}
        edgeCount={edges.length}
      />

      {/* MAIN BODY AREA: Sidebar + Canvas + Inspector */}
      <div className="flex-1 flex overflow-hidden relative">
        <Sidebar 
          onLoadTemplate={handleLoadTemplate}
          isCollapsed={isSidebarCollapsed}
          setIsCollapsed={setIsSidebarCollapsed}
        />

        <WorkflowCanvas
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          setNodes={setNodes}
          setEdges={setEdges}
          onNodeSelect={handleNodeSelect}
        />
      </div>

      {selection.node && (
        <NodePopup
          node={selection.node}
          anchor={selection.anchor}
          onUpdateNode={handleUpdateNode}
          onDeleteNode={handleDeleteNode}
          onClose={() => setSelection({ node: null, anchor: null })}
        />
      )}

      {/* BOTTOM CONSOLE & LOGS */}
      <BottomConsole 
        logs={logs}
        isConsoleOpen={isConsoleOpen}
        setIsConsoleOpen={setIsConsoleOpen}
        onClearLogs={() => setLogs([])}
      />

      {/* MODALS */}
      <CommandPalette 
        isOpen={isCommandPaletteOpen}
        onClose={setIsCommandPaletteOpen}
        onAddNode={handleAddNodeFromPalette}
      />

      <AiCopilotModal 
        isOpen={isAiCopilotOpen}
        onClose={() => setIsAiCopilotOpen(false)}
        onGenerateWorkflow={handleGenerateAiWorkflow}
      />

      <TemplatesModal 
        isOpen={isTemplatesOpen}
        onClose={() => setIsTemplatesOpen(false)}
        onLoadTemplate={handleLoadTemplate}
      />
    </div>
  );
}

export default function WorkflowBuilder() {
  return (
    <ReactFlowProvider>
      <WorkflowBuilderContent />
    </ReactFlowProvider>
  );
}
