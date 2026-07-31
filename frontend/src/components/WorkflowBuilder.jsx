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
import GoogleDriveVerificationModal from './GoogleDriveVerificationModal';
import { WORKFLOW_TEMPLATES } from '../data/templates';
import { executeWorkflowGraph } from '../lib/executeWorkflow';

// Default initial state is blank playground (empty canvas)
const INITIAL_NODES = [];
const INITIAL_EDGES = [];

// Version key: bump this to force-clear old cached canvas state
const CANVAS_VERSION = 'v2-blank';

function loadPersistedNodes() {
  try {
    const version = localStorage.getItem('cyberverse_canvas_version');
    if (version !== CANVAS_VERSION) {
      // Old cached state (pre-blank-playground) - wipe it
      localStorage.removeItem('cyberverse_canvas_nodes');
      localStorage.removeItem('cyberverse_canvas_edges');
      localStorage.setItem('cyberverse_canvas_version', CANVAS_VERSION);
      return INITIAL_NODES;
    }
    const saved = localStorage.getItem('cyberverse_canvas_nodes');
    return saved ? JSON.parse(saved) : INITIAL_NODES;
  } catch {
    return INITIAL_NODES;
  }
}

function loadPersistedEdges() {
  try {
    const version = localStorage.getItem('cyberverse_canvas_version');
    if (version !== CANVAS_VERSION) return INITIAL_EDGES;
    const saved = localStorage.getItem('cyberverse_canvas_edges');
    return saved ? JSON.parse(saved) : INITIAL_EDGES;
  } catch {
    return INITIAL_EDGES;
  }
}

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
  // Load nodes and edges from localStorage if available, defaulting to blank canvas
  const [nodes, setNodes, onNodesChange] = useNodesState(() => loadPersistedNodes());

  const [edges, setEdges, onEdgesChange] = useEdgesState(() => loadPersistedEdges());
  
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
  const [isGDriveModalOpen, setIsGDriveModalOpen] = useState(false);

  const [logs, setLogs] = useState([
    { id: 1, type: 'info', timestamp: new Date().toLocaleTimeString(), message: '[CyberVerse Engine] Ready for multi-agent execution.' }
  ]);

  // Save canvas state to localStorage whenever nodes or edges update
  useEffect(() => {
    try {
      localStorage.setItem('cyberverse_canvas_nodes', JSON.stringify(nodes));
      localStorage.setItem('cyberverse_canvas_edges', JSON.stringify(edges));
    } catch (err) {
      console.error('Failed to persist canvas to localStorage:', err);
    }
  }, [nodes, edges]);

  const addLog = useCallback((type, message) => {
    setLogs(prev => [
      ...prev,
      { id: Date.now(), type, timestamp: new Date().toLocaleTimeString(), message }
    ]);
  }, []);

  // Register any webhook-trigger node's downstream agent with the backend
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

  // Clear Canvas (returns to blank playground)
  const handleClearCanvas = useCallback(() => {
    setIsSaved(false);
    setNodes([]);
    setEdges([]);
    setSelection({ node: null, anchor: null });
    try {
      localStorage.removeItem('cyberverse_canvas_nodes');
      localStorage.removeItem('cyberverse_canvas_edges');
    } catch {}
    addLog('info', 'Cleared canvas. Returned to blank playground.');
  }, [setNodes, setEdges, addLog]);

  const handleNodeSelect = useCallback((node, anchor) => {
    setSelection({ node, anchor });
  }, []);

  // Real dynamic execution
  const handleRunWorkflow = useCallback(async () => {
    if (nodes.length === 0) {
      addLog('warn', 'Nothing to run - add some nodes or load a template onto the canvas first.');
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

  // Load preset template
  const handleLoadTemplate = useCallback((templateId) => {
    setIsSaved(false);
    const tmpl = WORKFLOW_TEMPLATES.find(t => t.id === templateId);
    if (!tmpl) {
      setNodes([]);
      setEdges([]);
      addLog('warn', `Unknown template "${templateId}" - cleared canvas.`);
      return;
    }
    setNodes(JSON.parse(JSON.stringify(tmpl.nodes)));
    setEdges(JSON.parse(JSON.stringify(tmpl.edges)));
    addLog('info', `Loaded template: ${tmpl.title}`);
    if (templateId === 'template-document-trust' || templateId === 'template-certificate-verification') {
      setIsGDriveModalOpen(true);
    }
  }, [setNodes, setEdges, addLog]);

  // Generate AI Workflow
  const handleGenerateAiWorkflow = useCallback((promptText) => {
    setIsSaved(false);
    addLog('info', `[AI Copilot] Generating flow graph for prompt: "${promptText.substring(0, 40)}..."`);
    handleLoadTemplate('template-document-trust');
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
        onOpenGDriveModal={() => setIsGDriveModalOpen(true)}
        onSaveWorkflow={() => setIsSaved(true)}
        onClearCanvas={handleClearCanvas}
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

      <GoogleDriveVerificationModal
        isOpen={isGDriveModalOpen}
        onClose={() => setIsGDriveModalOpen(false)}
        setNodes={setNodes}
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
