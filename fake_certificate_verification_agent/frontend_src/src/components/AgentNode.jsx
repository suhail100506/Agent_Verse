import React from 'react';
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { Loader2, CheckCircle2, Trash2 } from 'lucide-react';

export default function AgentNode({ id, data, selected }) {
  const { setNodes, setEdges } = useReactFlow();
  const isCompleted = data.status === 'completed';
  const isRunning = data.status === 'running';

  const onDelete = (e) => {
    e.stopPropagation();
    setNodes((nodes) => nodes.filter((n) => n.id !== id));
    setEdges((edges) => edges.filter((edge) => edge.source !== id && edge.target !== id));
  };

  return (
    <div className={`px-5 py-3 rounded-2xl border transition-all duration-300 shadow-xl min-w-[220px] text-center relative group ${isRunning ? 'bg-sky-950/90 border-sky-400 text-white shadow-sky-500/50 animate-pulse scale-105' : isCompleted ? 'bg-slate-950/90 border-emerald-500/60 text-slate-100' : 'bg-[#0f172a]/90 border-slate-700/80 text-slate-200 hover:border-sky-500/50'} ${selected ? 'border-sky-500 ring-2 ring-sky-500/50' : ''}`}>
      <Handle type="target" position={Position.Top} className="!bg-sky-400 !w-2.5 !h-2.5 !border-2 !border-slate-900" />
      
      <button 
        onClick={onDelete}
        className="absolute -top-3 -right-3 p-1.5 rounded-full bg-slate-800 border border-slate-600 text-rose-400 shadow-md opacity-0 group-hover:opacity-100 transition-opacity hover:bg-rose-500 hover:text-white hover:border-rose-500 z-10"
        title="Delete Node"
      >
        <Trash2 className="w-3.5 h-3.5" />
      </button>

      <div className="flex items-center justify-center gap-2 font-bold text-xs">
        <span className="text-base">{data.icon}</span>
        <span className="tracking-wide">{data.label}</span>
      </div>
      
      {data.subtitle && (
        <div className="text-[10px] text-slate-400 mt-1 font-medium truncate">
          {data.subtitle}
        </div>
      )}
      
      {isRunning && (
        <span className="absolute -top-2 -left-2 p-1 rounded-full bg-sky-500 text-slate-950 shadow-md">
          <Loader2 className="w-3 h-3 animate-spin" />
        </span>
      )}
      
      {isCompleted && (
        <span className="absolute -top-2 -left-2 p-1 rounded-full bg-emerald-500 text-slate-950 shadow-md">
          <CheckCircle2 className="w-3 h-3" />
        </span>
      )}
      
      <Handle type="source" position={Position.Bottom} className="!bg-sky-400 !w-2.5 !h-2.5 !border-2 !border-slate-900" />
    </div>
  );
}
