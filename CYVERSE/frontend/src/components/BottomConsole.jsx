import React, { useState } from 'react';
import { 
  Terminal, 
  ChevronDown, 
  ChevronUp, 
  Trash2, 
  FileJson, 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  Search, 
  Maximize2,
  Copy
} from 'lucide-react';

export default function BottomConsole({ logs, isConsoleOpen, setIsConsoleOpen, onClearLogs }) {
  const [activeTab, setActiveTab] = useState('logs');
  const [searchLog, setSearchLog] = useState('');

  const defaultLogs = [
    { id: 1, type: 'info', timestamp: '09:40:01', message: '[CyberVerse] Multi-Agent Workflow Engine initialized.' },
    { id: 2, type: 'info', timestamp: '09:40:02', message: '[Orchestrator] Connected to 10 sub-agent routes.' },
    { id: 3, type: 'success', timestamp: '09:40:05', message: '[PKI Registry] Cryptographic root certificates loaded.' },
  ];

  const displayLogs = logs.length > 0 ? logs : defaultLogs;

  const filteredLogs = displayLogs.filter(l => 
    l.message.toLowerCase().includes(searchLog.toLowerCase()) || 
    l.timestamp.includes(searchLog)
  );

  return (
    <div 
      className={`w-full bg-[#252525]/95 backdrop-blur-md border-t border-black/20 flex flex-col shrink-0 transition-all duration-300 z-30 select-none ${
        isConsoleOpen ? 'h-52' : 'h-10'
      }`}
    >
      {/* CONSOLE HEADER BAR */}
      <div className="h-10 px-4 bg-[#252525] border-b border-black/20 flex items-center justify-between shrink-0 text-xs">
        {/* LEFT: TABS */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => {
              setIsConsoleOpen(true);
              setActiveTab('logs');
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              isConsoleOpen && activeTab === 'logs' 
                ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm' 
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Execution Logs</span>
            <span className="px-1.5 py-0.5 rounded bg-black/20 text-[9px] font-mono text-zinc-400 border border-white/5">
              {displayLogs.length}
            </span>
          </button>

          <button
            onClick={() => {
              setIsConsoleOpen(true);
              setActiveTab('json');
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              isConsoleOpen && activeTab === 'json' 
                ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm' 
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5'
            }`}
          >
            <FileJson className="w-3.5 h-3.5 text-cyan-500" />
            <span>API Response</span>
          </button>

          <button
            onClick={() => {
              setIsConsoleOpen(true);
              setActiveTab('metrics');
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium transition-all ${
              isConsoleOpen && activeTab === 'metrics' 
                ? 'bg-[#3B3B3B] text-zinc-100 shadow-sm' 
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/5'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-emerald-500" />
            <span>Metrics</span>
          </button>
        </div>

        {/* RIGHT: SEARCH & COLLAPSE CONTROLS */}
        <div className="flex items-center gap-3">
          {isConsoleOpen && (
            <>
              <div className="relative group">
                <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1.5 group-focus-within:text-indigo-400 transition-colors" />
                <input
                  type="text"
                  placeholder="Filter logs..."
                  value={searchLog}
                  onChange={(e) => setSearchLog(e.target.value)}
                  className="bg-[#1E1E1E] border border-black/20 rounded-md pl-8 pr-2 py-1 text-[11px] text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-indigo-500/50 focus:ring-1 focus:ring-indigo-500/30 transition-all shadow-inner w-48"
                />
              </div>

              <button
                onClick={onClearLogs}
                title="Clear console"
                className="p-1.5 rounded-md text-zinc-500 hover:text-rose-400 hover:bg-white/5 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </>
          )}

          <button
            onClick={() => setIsConsoleOpen(!isConsoleOpen)}
            className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-100 hover:bg-white/5 transition-colors ml-2"
          >
            {isConsoleOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* EXPANDABLE CONSOLE BODY */}
      {isConsoleOpen && (
        <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] custom-scrollbar bg-[#1A1A1A]">
          {activeTab === 'logs' ? (
            <div className="space-y-0.5">
              {filteredLogs.map((log, idx) => (
                <div key={idx} className="flex items-start gap-3 hover:bg-black/10 px-2 py-1 rounded-md leading-relaxed transition-colors">
                  <span className="text-zinc-500 text-[10px] shrink-0 font-medium w-16">{log.timestamp}</span>
                  <span className={`shrink-0 font-bold uppercase text-[10px] w-16 ${
                    log.type === 'error' 
                      ? 'text-rose-500' 
                      : log.type === 'success' 
                      ? 'text-emerald-500' 
                      : log.type === 'warn' 
                      ? 'text-amber-500' 
                      : 'text-cyan-500'
                  }`}>
                    [{log.type || 'INFO'}]
                  </span>
                  <span className="text-zinc-300 select-text">{log.message}</span>
                </div>
              ))}
            </div>
          ) : activeTab === 'json' ? (
            <div className="p-2 text-indigo-300 font-mono text-[11px]">
              <div className="text-zinc-500 text-[10px] mb-2 font-sans flex justify-between items-center font-medium">
                <span>Latest Multi-Agent Verification Output</span>
                <span className="text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded">200 OK • 1.2s</span>
              </div>
              <pre className="p-4 rounded-xl bg-[#222222] border border-black/20 overflow-x-auto shadow-inner leading-relaxed">
{`{
  "status": "Verified",
  "confidence": 0.985,
  "risk_level": "Low",
  "agents_evaluated": [
    "Document Extraction Agent",
    "PKI Root Registry",
    "Visual Forensics Agent"
  ],
  "summary": "Diploma seal matching authentic university PKI root. Zero pixel manipulation."
}`}
              </pre>
            </div>
          ) : (
            /* SYSTEM METRICS TAB */
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 p-2 font-sans">
              <div className="p-4 rounded-xl bg-[#222222] border border-black/20 flex flex-col justify-center">
                <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1.5">Canvas Latency</span>
                <span className="text-xl font-bold text-emerald-400">12<span className="text-xs text-emerald-500/50 ml-1">ms</span></span>
              </div>
              <div className="p-4 rounded-xl bg-[#222222] border border-black/20 flex flex-col justify-center">
                <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1.5">Active Memory</span>
                <span className="text-xl font-bold text-cyan-400">42<span className="text-xs text-cyan-500/50 ml-1">MB</span></span>
              </div>
              <div className="p-4 rounded-xl bg-[#222222] border border-black/20 flex flex-col justify-center">
                <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1.5">FastAPI Backend</span>
                <span className="text-xl font-bold text-emerald-400">Live</span>
              </div>
              <div className="p-4 rounded-xl bg-[#222222] border border-black/20 flex flex-col justify-center">
                <span className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1.5">Agents Active</span>
                <span className="text-xl font-bold text-indigo-400">10<span className="text-xs text-indigo-500/50 ml-1">/ 10</span></span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
