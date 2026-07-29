import React, { useCallback, useState, useRef } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap, 
  useNodesState, 
  useEdgesState, 
  addEdge,
  reconnectEdge,
  useReactFlow,
  ReactFlowProvider,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import AgentNode from './AgentNode';

const nodeTypes = { agentNode: AgentNode };

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
  {
    id: 'edge-1-2',
    source: 'node-trigger-ingest',
    target: 'node-orchestrator',
    animated: true,
    style: { stroke: '#71717a', strokeWidth: 1.5 }
  },
  {
    id: 'edge-2-3',
    source: 'node-orchestrator',
    target: 'node-doc-forensics',
    animated: true,
    style: { stroke: '#71717a', strokeWidth: 1.5 }
  },
  {
    id: 'edge-2-4',
    source: 'node-orchestrator',
    target: 'node-malware-scan',
    animated: true,
    style: { stroke: '#71717a', strokeWidth: 1.5 }
  },
  {
    id: 'edge-3-5',
    source: 'node-doc-forensics',
    target: 'node-report',
    animated: true,
    style: { stroke: '#71717a', strokeWidth: 1.5 }
  },
  {
    id: 'edge-4-5',
    source: 'node-malware-scan',
    target: 'node-report',
    animated: true,
    style: { stroke: '#71717a', strokeWidth: 1.5 }
  }
];

export default function WorkflowCanvas({ 
  nodes, 
  edges, 
  onNodesChange, 
  onEdgesChange, 
  setNodes, 
  setEdges,
  onNodeSelect
}) {
  const { screenToFlowPosition, fitView } = useReactFlow();

  const onConnect = useCallback(
    (params) => setEdges((eds) => addEdge({ 
      ...params, 
      animated: true, 
      style: { stroke: '#71717a', strokeWidth: 1.5 } 
    }, eds)),
    [setEdges],
  );

  const onReconnect = useCallback(
    (oldEdge, newConnection) => setEdges((els) => reconnectEdge(oldEdge, newConnection, els)),
    [setEdges],
  );

  const onDragOver = useCallback((event) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event) => {
      event.preventDefault();

      const type = event.dataTransfer.getData('application/reactflow/agent');
      if (!type) return;

      const agentData = JSON.parse(type);
      const position = screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      const newNode = {
        id: `node-${Date.now()}`,
        type: 'agentNode',
        position,
        data: { ...agentData, status: 'idle' },
      };

      setNodes((nds) => nds.concat(newNode));
    },
    [screenToFlowPosition, setNodes],
  );

  const onNodeClick = useCallback((event, node) => {
    onNodeSelect(node, { x: event.clientX, y: event.clientY });
  }, [onNodeSelect]);

  const onPaneClick = useCallback(() => {
    onNodeSelect(null, null);
  }, [onNodeSelect]);

  const displayEdges = edges.map(edge => ({
    ...edge,
    type: 'default',
    animated: edge.animated || !edge.selected,
    style: {
      ...edge.style,
      stroke: edge.selected ? '#e4e4e7' : (edge.style?.stroke || '#71717a'),
      strokeWidth: edge.selected ? 2.5 : (edge.style?.strokeWidth || 1.5)
    }
  }));

  return (
    <div 
      className="flex-1 w-full h-full bg-[#1F1F1F] relative overflow-hidden" 
      onDragOver={onDragOver} 
      onDrop={onDrop}
    >
      <div className="absolute inset-0 bg-grid-pattern opacity-40 mix-blend-screen pointer-events-none z-0" />
      <ReactFlow
        nodes={nodes}
        edges={displayEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onReconnect={onReconnect}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        deleteKeyCode={["Backspace", "Delete"]}
        className="react-flow-custom z-10"
      >
        <Controls className="!bg-[#2B2B2B]/80 !border-white/10 !text-zinc-300 !rounded-lg !shadow-xl !p-1 backdrop-blur-md" />
        
        <MiniMap 
          nodeColor={(node) => {
            if (node.data.status === 'completed') return '#10b981';
            if (node.data.status === 'running') return '#6366f1';
            if (node.data.status === 'error') return '#f43f5e';
            return '#3B3B3B';
          }}
          maskColor="rgba(31, 31, 31, 0.7)" 
          style={{ backgroundColor: 'rgba(43, 43, 43, 0.8)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.05)' }} 
        />
      </ReactFlow>
    </div>
  );
}
