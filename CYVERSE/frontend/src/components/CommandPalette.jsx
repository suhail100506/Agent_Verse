import React, { useState, useEffect } from 'react';
import { NODE_LIBRARY } from '../data/nodeLibrary';
import { Search, Zap, Plus, ArrowRight, X } from 'lucide-react';

export default function CommandPalette({ isOpen, onClose, onAddNode }) {
  const [query, setQuery] = useState('');

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onClose(!isOpen);
      }
      if (e.key === 'Escape' && isOpen) {
        onClose(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const filteredNodes = NODE_LIBRARY.filter(node => 
    node.name.toLowerCase().includes(query.toLowerCase()) || 
    node.subtitle.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-start justify-center pt-24 p-4 select-none animate-fadeIn">
      <div className="w-full max-w-xl bg-[#0b0f14] border border-[#1e293b] rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* INPUT HEADER */}
        <div className="p-3.5 border-b border-[#1e293b] flex items-center gap-3">
          <Search className="w-4 h-4 text-indigo-400 shrink-0" />
          <input
            type="text"
            autoFocus
            placeholder="Type a command or search nodes (e.g. Master Orchestrator, Malware PE)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button onClick={() => onClose(false)} className="text-slate-500 hover:text-white p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* RESULTS LIST */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-1 custom-scrollbar">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-500 px-3 py-1">
            Available Components & Agents ({filteredNodes.length})
          </div>

          {filteredNodes.map((node) => (
            <div
              key={node.id}
              onClick={() => {
                onAddNode(node.defaultData);
                onClose(false);
              }}
              className="px-3 py-2.5 rounded-xl hover:bg-[#161b22] hover:border hover:border-[#1e293b] cursor-pointer flex items-center justify-between group transition-all"
            >
              <div className="flex items-center gap-3">
                <div className="w-7 h-7 rounded-lg bg-[#161b22] border border-[#1e293b] flex items-center justify-center text-sm">
                  {node.defaultData.icon || '⚡'}
                </div>
                <div>
                  <h4 className="text-xs font-bold text-slate-200 group-hover:text-indigo-300">
                    {node.name}
                  </h4>
                  <span className="text-[10px] text-slate-400 font-medium">{node.subtitle}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-[9px] font-mono border border-indigo-500/20">
                  {node.badge}
                </span>
                <Plus className="w-4 h-4 text-slate-500 group-hover:text-indigo-400 transition-colors" />
              </div>
            </div>
          ))}
        </div>

        {/* FOOTER */}
        <div className="px-4 py-2 border-t border-[#1e293b] bg-[#0e131b] flex items-center justify-between text-[10px] text-slate-500 font-mono">
          <span>Navigate with ↑ ↓ and Press Enter</span>
          <span>Press ESC to close</span>
        </div>
      </div>
    </div>
  );
}
