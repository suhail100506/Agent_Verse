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
import { WORKFLOW_TEMPLATES } from '../data/templates';

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

function WorkflowBuilderContent() {
  const [nodes, setNodes, onNodesChange] = useNodesState(INITIAL_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES);
  
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

  // Master execution simulation
  const handleRunWorkflow = useCallback(async () => {
    setIsRunning(true);
    setIsConsoleOpen(true);
    addLog('info', '[Master Kickoff] Initiating sequential execution across workflow DAG...');

    // Reset statuses
    setNodes(nds => nds.map(n => ({ ...n, data: { ...n.data, status: 'idle' } })));

    // Step 1: Ingest
    addLog('info', '[Node 1/4] Running User Payload Ingest...');
    setNodes(nds => nds.map(n => n.id === 'node-trigger-ingest' ? { ...n, data: { ...n.data, status: 'running' } } : n));
    await new Promise(r => setTimeout(r, 700));
    setNodes(nds => nds.map(n => n.id === 'node-trigger-ingest' ? { ...n, data: { ...n.data, status: 'completed' } } : n));
    addLog('success', '[Node 1/4] Ingest Complete. Received payload string.');

    // Step 2: Master Orchestrator
    addLog('info', '[Node 2/4] Dispatched to Master Cyber Orchestrator...');
    setNodes(nds => nds.map(n => n.id === 'node-orchestrator' ? { ...n, data: { ...n.data, status: 'running' } } : n));
    await new Promise(r => setTimeout(r, 900));
    setNodes(nds => nds.map(n => n.id === 'node-orchestrator' ? { ...n, data: { ...n.data, status: 'completed' } } : n));
    addLog('success', '[Node 2/4] Intent routed to Document Extraction & Malware Analyzer.');

    // Step 3: Sub-agents
    addLog('info', '[Node 3/4] Parallel analysis: Running OCR Forensics & YARA PE Scan...');
    setNodes(nds => nds.map(n => ['node-doc-forensics', 'node-malware-scan'].includes(n.id) ? { ...n, data: { ...n.data, status: 'running' } } : n));
    await new Promise(r => setTimeout(r, 1100));
    setNodes(nds => nds.map(n => ['node-doc-forensics', 'node-malware-scan'].includes(n.id) ? { ...n, data: { ...n.data, status: 'completed' } } : n));
    addLog('success', '[Node 3/4] Zero malware signatures detected. Certificate PKI valid.');

    // Step 4: Final Report
    addLog('info', '[Node 4/4] Generating Final PDF & JSON Audit Report...');
    setNodes(nds => nds.map(n => n.id === 'node-report' ? { ...n, data: { ...n.data, status: 'running' } } : n));
    await new Promise(r => setTimeout(r, 600));
    setNodes(nds => nds.map(n => n.id === 'node-report' ? { ...n, data: { ...n.data, status: 'completed' } } : n));
    addLog('success', '[Workflow Complete] All 5 nodes executed successfully in 3.3s. Security Score: 98/100.');

    setIsRunning(false);
  }, [setNodes, addLog]);

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
