import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { Loader2, CheckCircle2 } from 'lucide-react';

export default function AgentNode({ data, selected }) {
  const isCompleted = data.status === 'completed';
  const isRunning = data.status === 'running';

  return (
    <div className={`px-5 py-3 rounded-2xl border transition-all duration-300 shadow-xl min-w-[220px] text-center relative group ${isRunning ? 'bg-sky-950/90 border-sky-400 text-white shadow-sky-500/50 animate-pulse scale-105' : isCompleted ? 'bg-slate-950/90 border-emerald-500/60 text-slate-100' : 'bg-[#0f172a]/90 border-slate-700/80 text-slate-200 hover:border-sky-500/50'} ${selected ? 'border-sky-500 ring-2 ring-sky-500/50' : ''}`}>
      <Handle type="target" position={Position.Top} className="!bg-sky-400 !w-2.5 !h-2.5 !border-2 !border-slate-900" />

      <div className="flex items-center justify-center gap-2 font-bold text-xs">
        <span className="text-base">{data.icon}</span>
        <span className="tracking-wide">{data.label}</span>
      </div>
      
      {data.isTextBox ? (
        <div className="mt-2">
          <input 
            type="text" 
            placeholder="Type here..." 
            className="w-full bg-slate-900/50 border border-slate-700 rounded p-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 nodrag"
          />
        </div>
      ) : (
        data.subtitle && (
          <div className="text-[10px] text-slate-400 mt-1 font-medium truncate">
            {data.subtitle}
          </div>
        )
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
