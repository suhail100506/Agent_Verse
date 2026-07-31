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
  MarkerType,
  SelectionMode
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import AgentNode from './AgentNode';

const nodeTypes = { agentNode: AgentNode };



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
        selectionOnDrag
        selectionMode={SelectionMode.Partial}
        panOnDrag={[1, 2]}
        multiSelectionKeyCode={["Shift", "Meta", "Control"]}
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
