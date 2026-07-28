import React, { useState } from 'react';
import { Handle, Position, useReactFlow } from '@xyflow/react';
import { Loader2, CheckCircle2 } from 'lucide-react';

export default function AgentNode({ id, data, selected }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();
  
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
        <div className="mt-2 text-left flex flex-col gap-2">
          <input 
            type="text" 
            placeholder="Enter payload here..." 
            id={`test-input-${data.id}`}
            onKeyDown={async (e) => {
              if (e.key === 'Enter' && e.target.value) {
                document.getElementById(`test-btn-${data.id}`)?.click();
              }
            }}
            className="w-full bg-slate-900/50 border border-slate-700 rounded p-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500 nodrag"
          />
          <button
            id={`test-btn-${data.id}`}
            disabled={loading}
            onClick={async () => {
              const val = document.getElementById(`test-input-${data.id}`)?.value;
              if (!val) return;
              
              setLoading(true);
              setResult(null);
              
              const allEdges = getEdges();
              const outEdge = allEdges.find(e => e.source === id);
              let targetNodeId = null;

              if (outEdge) {
                targetNodeId = outEdge.target;
                setEdges(eds => eds.map(e => e.id === outEdge.id ? { ...e, animated: true, style: { stroke: '#f97316', strokeWidth: 4 } } : e));
                setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'running' } } : n));
                
                await new Promise(r => setTimeout(r, 600)); // Visual delay for animation
              }
              
              try {
                const formData = new FormData();
                formData.append('url_or_text', val);
                const res = await fetch('http://localhost:8001/api/analyze/phishing', {
                  method: 'POST',
                  body: formData
                });
                const json = await res.json();
                setResult(json);
                
                if (targetNodeId) {
                  setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'completed' } } : n));
                  setEdges(eds => eds.map(e => e.id === outEdge.id ? { ...e, style: { stroke: '#38bdf8', strokeWidth: 2 } } : e));
                  
                  // Spawn new node
                  const targetNode = getNodes().find(n => n.id === targetNodeId);
                  if (targetNode) {
                    const alertNodeId = `alert-${Date.now()}`;
                    const isFake = json.status === 'Fake';
                    const alertNode = {
                      id: alertNodeId,
                      type: 'agentNode',
                      position: { x: targetNode.position.x, y: targetNode.position.y + 150 },
                      data: {
                        icon: isFake ? "🚨" : "✅",
                        label: isFake ? "Suspicious Email Found" : "Email Verified Safe",
                        subtitle: isFake ? `Email Alert: ${json.email_delivery_status}` : 'No alert dispatched',
                        status: 'completed'
                      }
                    };
                    setNodes(nds => nds.concat(alertNode));
                    setEdges(eds => eds.concat({
                      id: `e-${targetNodeId}-${alertNodeId}`,
                      source: targetNodeId,
                      target: alertNodeId,
                      animated: true,
                      style: { stroke: isFake ? '#f43f5e' : '#10b981', strokeWidth: 3 }
                    }));
                  }
                }
              } catch (err) {
                setResult({ error: 'Failed to connect to API' });
                if (targetNodeId) {
                  setNodes(nds => nds.map(n => n.id === targetNodeId ? { ...n, data: { ...n.data, status: 'idle' } } : n));
                  setEdges(eds => eds.map(e => e.id === outEdge.id ? { ...e, style: { stroke: '#38bdf8', strokeWidth: 2 } } : e));
                }
              } finally {
                setLoading(false);
              }
            }}
            className="w-full py-1.5 rounded bg-sky-500 hover:bg-sky-400 text-slate-950 font-bold text-[11px] transition-colors flex items-center justify-center gap-1 shadow-md shadow-sky-500/20 disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
            {loading ? "Running..." : "▶ Run Simulation"}
          </button>
          
          {result && !result.error && (
            <div className="text-[10px] text-slate-300 bg-slate-900 p-2 rounded border border-slate-700 mt-1">
              <div className="mb-1"><span className="text-slate-500">Status:</span> <strong className={result.status === 'Fake' ? 'text-rose-400' : 'text-emerald-400'}>{result.status}</strong></div>
              <div className="mb-1"><span className="text-slate-500">Risk:</span> <strong>{result.risk_level}</strong></div>
              <div className="mb-1"><span className="text-slate-500">Conf:</span> <strong>{(result.confidence * 100).toFixed(0)}%</strong></div>
              <div className="mb-1"><span className="text-slate-500">Reason:</span> {result.summary}</div>
              
              {result.email_delivery_status && (
                <div className={`mt-2 pt-2 border-t border-slate-700 font-bold ${result.email_delivery_status === 'success' ? 'text-emerald-400' : result.email_delivery_status === 'failed' ? 'text-rose-400' : 'text-slate-400'}`}>
                  Email Alert: {result.email_delivery_status.toUpperCase()}
                  {result.email_delivery_error && <div className="text-[9px] font-normal text-rose-300 mt-0.5">{result.email_delivery_error}</div>}
                </div>
              )}
            </div>
          )}
          {result && result.error && (
            <div className="text-[10px] text-rose-400 bg-rose-950/50 p-2 rounded border border-rose-900">
              {result.error}
            </div>
          )}
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
