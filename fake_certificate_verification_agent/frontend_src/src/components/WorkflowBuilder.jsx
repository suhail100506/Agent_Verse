import React, { useCallback, useRef, useState } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap, 
  useNodesState, 
  useEdgesState, 
  addEdge,
  useReactFlow,
  ReactFlowProvider
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import AgentNode from './AgentNode';
import CustomEdge from './CustomEdge';

const nodeTypes = { agentNode: AgentNode };
const edgeTypes = { customEdge: CustomEdge };

const initialNodes = [
  { id: "node-user-upload", type: "agentNode", data: { icon: "📄", label: "User Payload Ingest", subtitle: "Payload Trigger Input" }, position: { x: 300, y: 20 } },
  { id: "node-doc-ext", type: "agentNode", data: { icon: "🤖", label: "Document Extraction Agent", subtitle: "OCR & Metadata Parsing" }, position: { x: 300, y: 110 } }
];

const initialEdges = [
  { id: "e1-2", source: "node-user-upload", target: "node-doc-ext", type: 'customEdge', animated: true, style: { stroke: "#38bdf8", strokeWidth: 2 } }
];

function WorkflowCanvas() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const { screenToFlowPosition } = useReactFlow();

  const onConnect = useCallback(
    (params) => setEdges((eds) => addEdge({ ...params, type: 'customEdge', animated: true, style: { stroke: "#38bdf8", strokeWidth: 2 } }, eds)),
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
        id: `node-${agentData.id}-${Date.now()}`,
        type: 'agentNode',
        position,
        data: { ...agentData, status: 'idle' },
      };

      setNodes((nds) => nds.concat(newNode));
    },
    [screenToFlowPosition, setNodes],
  );

  return (
    <div className="flex-1 relative w-full h-full bg-[#07090e]" onDragOver={onDragOver} onDrop={onDrop}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        deleteKeyCode={["Backspace", "Delete"]} // Natively ensures selection deletion!
        className="react-flow-custom"
      >
        <Background color="#1e293b" gap={24} size={1} />
        <Controls className="!bg-slate-900/90 !border-slate-800 !text-slate-300 !rounded-xl !shadow-2xl" />
        <MiniMap 
          nodeColor="#0f172a" 
          maskColor="rgba(7, 9, 14, 0.8)" 
          style={{ backgroundColor: '#07090e' }} 
        />
      </ReactFlow>
    </div>
  );
}

export default function WorkflowBuilder() {
  return (
    <ReactFlowProvider>
      <WorkflowCanvas />
    </ReactFlowProvider>
  );
}
