import React, { useState, useCallback, useEffect } from 'react';
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

function WorkflowBuilderContent() {
  // Load nodes and edges from localStorage if available, defaulting to blank canvas
  const [nodes, setNodes, onNodesChange] = useNodesState(() => loadPersistedNodes());

  const [edges, setEdges, onEdgesChange] = useEdgesState(() => loadPersistedEdges());
  
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
