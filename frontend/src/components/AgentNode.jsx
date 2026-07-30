import React, { useState } from 'react';
import { Handle, Position, useReactFlow } from '@xyflow/react';
import {
  Loader2,
  CheckCircle2,
  AlertCircle,
  Play,
  MoreHorizontal,
  Copy,
  Trash2,
  Terminal,
  Settings2,
  Upload,
  FileText,
  Fish,
  Bug,
  BadgeCheck,
  Key,
  AlertTriangle,
  CreditCard,
  FileSearch,
  Lock
} from 'lucide-react';

const ICON_MAP = {
  Fish, Bug, BadgeCheck, Key, AlertTriangle, CreditCard, FileSearch, Lock
};
import { AGENT_ROUTES, DEFAULT_ROUTE, buildAgentFormData } from '../data/agentRoutes';

const API_BASE = 'http://localhost:8000';

export default function AgentNode({ id, data, selected }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const { getNodes, getEdges, setNodes, setEdges, deleteElements } = useReactFlow();
  const [showMenu, setShowMenu] = useState(false);

  const isCompleted = data.status === 'completed';
  const isRunning = data.status === 'running';
  const isError = data.status === 'error';

  // Node duplicate handler
  const handleDuplicate = (e) => {
    e.stopPropagation();
    setShowMenu(false);
    const existingNode = getNodes().find(n => n.id === id);
    if (!existingNode) return;

    const newNode = {
      ...existingNode,
      id: `node-${Date.now()}`,
      position: {
        x: existingNode.position.x + 40,
        y: existingNode.position.y + 40,
      },
      selected: false
    };
    setNodes(nds => nds.concat(newNode));
  };

  // Node delete handler
  const handleDelete = (e) => {
    e.stopPropagation();
    setShowMenu(false);
    deleteElements({ nodes: [{ id }] });
  };

  return (
    <div 
      className={`relative group rounded-xl transition-all duration-300 min-w-[260px] max-w-[320px] bg-zinc-900/80 backdrop-blur-xl border ${
        isRunning 
          ? 'border-indigo-500/50 shadow-[0_0_20px_rgba(99,102,241,0.15)] ring-1 ring-indigo-500/20' 
          : isCompleted 
          ? 'border-emerald-500/30 shadow-[0_0_15px_rgba(16,185,129,0.1)]' 
          : isError
          ? 'border-rose-500/50 shadow-[0_0_15px_rgba(244,63,94,0.15)] ring-1 ring-rose-500/20'
          : selected 
          ? 'border-zinc-500 shadow-[0_0_15px_rgba(255,255,255,0.05)] ring-1 ring-zinc-500/30' 
          : 'border-white/5 hover:border-white/15 shadow-xl'
      }`}
    >
      {/* TOP TARGET HANDLE */}
      <Handle 
        type="target" 
        position={Position.Top} 
        className="!bg-zinc-800 !w-2.5 !h-2.5 !border-2 !border-zinc-950 hover:!bg-white transition-colors" 
      />

      {/* NODE HEADER */}
      <div className="p-3 border-b border-white/5 flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-zinc-800/80 border border-white/5 flex items-center justify-center text-sm shadow-inner shrink-0">
            {(() => {
              const IconComponent = ICON_MAP[data.icon];
              return IconComponent ? <IconComponent className="w-4 h-4 text-zinc-300" /> : (data.icon || '🤖');
            })()}
          </div>
          <div className="flex flex-col justify-center">
            <h3 className="font-semibold text-[13px] text-zinc-100 leading-tight">
              {data.label || 'Specialized Agent'}
            </h3>
            <p className="text-[11px] text-zinc-400 font-medium truncate max-w-[150px] mt-0.5">
              {data.subtitle || 'CyberVerse Node'}
            </p>
          </div>
        </div>

        {/* STATUS BADGE OR MENU */}
        <div className="flex items-center gap-1.5 mt-0.5">
          {isRunning && (
            <span className="flex items-center gap-1 text-[10px] font-medium text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded-md border border-indigo-500/20">
              <Loader2 className="w-3 h-3 animate-spin" /> Running
            </span>
          )}
          {isCompleted && (
            <span className="flex items-center gap-1 text-[10px] font-medium text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded-md border border-emerald-500/20">
              <CheckCircle2 className="w-3 h-3" /> Done
            </span>
          )}
          {isError && (
            <span className="flex items-center gap-1 text-[10px] font-medium text-rose-400 bg-rose-500/10 px-1.5 py-0.5 rounded-md border border-rose-500/20">
              <AlertCircle className="w-3 h-3" /> Error
            </span>
          )}

          {/* MORE MENU */}
          <div className="relative">
            <button
              onClick={(e) => {
                e.stopPropagation();
                setShowMenu(!showMenu);
              }}
              className="p-1 rounded-md text-zinc-500 hover:text-zinc-300 hover:bg-white/5 transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100"
            >
              <MoreHorizontal className="w-4 h-4" />
            </button>

            {showMenu && (
              <div className="absolute right-0 top-7 w-36 rounded-lg bg-zinc-900 border border-white/10 shadow-2xl py-1 z-50 text-[11px] font-medium text-zinc-300 backdrop-blur-xl">
                <button 
                  onClick={handleDuplicate}
                  className="w-full px-3 py-1.5 text-left hover:bg-white/5 hover:text-white flex items-center gap-2 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" /> Duplicate
                </button>
                <div className="h-px bg-white/5 my-0.5"></div>
                <button 
                  onClick={handleDelete}
                  className="w-full px-3 py-1.5 text-left hover:bg-rose-500/10 hover:text-rose-400 flex items-center gap-2 transition-colors"
                >
                  <Trash2 className="w-3.5 h-3.5" /> Delete
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* NODE BODY CONTENT */}
      <div className="p-3 text-[11px]">
        {data.isTextBox ? (
          /* INTERACTIVE TEST INPUT TRIGGER NODE */
          <div className="flex flex-col gap-2.5">
            <label className="text-[10px] font-medium text-zinc-400 flex items-center gap-1.5">
              <FileText className="w-3 h-3 text-zinc-500" /> Input Payload
            </label>
            <input 
              type="text" 
              placeholder="Enter query or payload..." 
              id={`test-input-${id}`}
              onKeyDown={async (e) => {
                if (e.key === 'Enter' && e.target.value) {
                  document.getElementById(`test-btn-${id}`)?.click();
                }
              }}
              className="w-full bg-zinc-950/50 border border-white/10 rounded-md p-2 text-[11px] text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500/50 transition-all nodrag"
            />
            
            <div className="flex items-center gap-2 text-[10px] text-zinc-600 font-medium justify-center my-0.5 uppercase tracking-wide">
              <div className="flex-1 h-px bg-white/5"></div>
              <span>OR</span>
              <div className="flex-1 h-px bg-white/5"></div>
            </div>

            <div className="relative group/file">
              <input
                type="file"
                id={`test-file-${id}`}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer nodrag z-10"
              />
              <div className="w-full bg-zinc-950/50 border border-white/5 border-dashed rounded-md p-2 text-center text-zinc-500 group-hover/file:border-zinc-500 group-hover/file:text-zinc-300 transition-colors flex items-center justify-center gap-2">
                <Upload className="w-3.5 h-3.5" />
                <span>Upload Document</span>
              </div>
            </div>

            <button
              id={`test-btn-${id}`}
              disabled={loading}
              onClick={async () => {
                const val = document.getElementById(`test-input-${id}`)?.value || '';
                const fileInput = document.getElementById(`test-file-${id}`);
                const fileVal = fileInput?.files?.[0];
                
                if (!val && !fileVal) return;
                
                setLoading(true);
                setResult(null);
                
                const allEdges = getEdges();
                const outEdge = allEdges.find(e => e.source === id);
                
                if (!outEdge) {
                  setResult({ error: 'Connect this node to an agent node to run execution!' });
                  setLoading(false);
                  return;
                }

                let targetNodeId = outEdge.target;

                if (outEdge) {
                  setEdges(eds => eds.map(e => e.id === outEdge.id ? { ...e, animated: true, style: { stroke: '#71717a', strokeWidth: 2 } } : e));
                  setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'running' } } : n));
                  await new Promise(r => setTimeout(r, 600)); 
                }
                
                try {
                  const targetNode = targetNodeId ? getNodes().find(n => n.id === targetNodeId) : null;
                  const route = targetNode ? (AGENT_ROUTES[targetNode.data.id] || DEFAULT_ROUTE) : DEFAULT_ROUTE;
                  const apiUrl = API_BASE + route.url;

                  const formData = buildAgentFormData(route, targetNode?.data, val, fileVal);

                  const res = await fetch(apiUrl, {
                    method: 'POST',
                    body: formData
                  });
                  const json = await res.json();
                  setResult(json);

                  if (targetNodeId) {
                    setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'completed' } } : n));
                    setEdges(eds => eds.map(e => e.id === outEdge.id ? { ...e, style: { stroke: '#a1a1aa', strokeWidth: 1.5 } } : e));
                  }
                } catch (err) {
                  setResult({ error: `Backend server not reachable at ${API_BASE}` });
                  if (targetNodeId) {
                    setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'error' } } : n));
                  }
                } finally {
                  setLoading(false);
                }
              }}
              className="w-full mt-1 py-1.5 rounded-md bg-white hover:bg-zinc-200 text-zinc-950 font-semibold text-[11px] transition-all flex items-center justify-center gap-1.5 disabled:opacity-50 active:scale-[0.98] shadow-sm"
            >
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
              <span>{loading ? "Executing..." : "Run Node"}</span>
            </button>
            
            {result && !result.error && (
              <div className="text-[10px] text-zinc-300 bg-zinc-950/50 p-2.5 rounded-md border border-white/5 mt-1 space-y-1.5 font-mono">
                <div className="flex items-center justify-between border-b border-white/5 pb-1">
                  <span className="text-zinc-500">Status</span>
                  <strong className={result.status === 'Fake' || result.status === 'Malicious' ? 'text-rose-400' : 'text-emerald-400'}>{result.status || 'Verified'}</strong>
                </div>
                <div className="flex items-center justify-between border-b border-white/5 pb-1">
                  <span className="text-zinc-500">Risk Score</span>
                  <strong>{result.risk_level || result.threat_score || 'Low'}</strong>
                </div>
                <div className="text-zinc-400 leading-relaxed pt-1">{result.summary || 'Scan complete'}</div>
              </div>
            )}
            {result && result.error && (
              <div className="text-[10px] text-rose-400 bg-rose-500/5 p-2.5 rounded-md border border-rose-500/20 font-mono flex items-start gap-2">
                <AlertCircle className="w-3 h-3 shrink-0 mt-0.5" />
                <span>{result.error}</span>
              </div>
            )}
          </div>
        ) : (
          /* STANDARD NODE METADATA DISPLAY */
          <div className="space-y-2.5">
            <div className="flex flex-col gap-1">
              <span className="text-[10px] text-zinc-500 font-medium">Input Port</span>
              <div className="px-2 py-1 bg-zinc-950/50 border border-white/5 rounded text-[10px] font-mono text-zinc-300">
                {data.inputLabel || 'payload_stream_in'}
              </div>
            </div>
            
            {data.isLogicNode && (
              <div className="px-2 py-1.5 rounded bg-amber-500/10 border border-amber-500/20 text-[10px] font-mono text-amber-400/90 flex flex-col gap-1">
                <span className="text-[9px] text-amber-500/60 uppercase font-sans font-bold">Branch Condition</span>
                <span>{data.conditionField} {data.conditionOperator} {data.conditionValue}</span>
              </div>
            )}

            <div className="flex items-center justify-between pt-2 text-[10px] font-mono text-zinc-500 border-t border-white/5">
              <span className="flex items-center gap-1"><span className="w-1 h-1 rounded-full bg-emerald-500"></span> 42ms</span>
              <span>18 MB</span>
            </div>
          </div>
        )}
      </div>

      {/* BOTTOM SOURCE HANDLE */}
      <Handle 
        type="source" 
        position={Position.Bottom} 
        className="!bg-zinc-800 !w-2.5 !h-2.5 !border-2 !border-zinc-950 hover:!bg-white transition-colors" 
      />
    </div>
  );
}
