import React from 'react';
import { WORKFLOW_TEMPLATES } from '../data/templates';
import { Sliders, X, Layers, ArrowRight, Check } from 'lucide-react';

export default function TemplatesModal({ isOpen, onClose, onLoadTemplate }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4 select-none">
      <div className="w-full max-w-2xl bg-[#0b0f14] border border-[#1e293b] rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* MODAL HEADER */}
        <div className="p-4 border-b border-[#1e293b] flex items-center justify-between bg-[#0e131b]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Sliders className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">Enterprise Workflow Templates</h3>
              <p className="text-[10px] text-slate-400 font-medium">Pre-configured multi-agent pipelines ready to execute</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* TEMPLATES LIST */}
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-3 max-h-96 overflow-y-auto custom-scrollbar">
          {WORKFLOW_TEMPLATES.map((tmpl) => (
            <div
              key={tmpl.id}
              onClick={() => {
                onLoadTemplate(tmpl.id);
                onClose();
              }}
              className="p-4 rounded-2xl bg-[#161b22] border border-[#1e293b] hover:border-cyan-500/50 hover:bg-[#1e293b]/70 cursor-pointer transition-all flex flex-col justify-between group"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 text-[10px] font-mono font-bold border border-cyan-500/20">
                    {tmpl.badge}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">{tmpl.nodeCount} Connected Nodes</span>
                </div>
                <h4 className="text-xs font-bold text-slate-100 group-hover:text-cyan-300 transition-colors mb-1">
                  {tmpl.title}
                </h4>
                <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                  {tmpl.description}
                </p>
              </div>

              <div className="flex items-center justify-between border-t border-[#1e293b]/60 pt-2 text-xs font-semibold text-cyan-400">
                <span>Load into Canvas</span>
                <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          ))}
        </div>

        {/* FOOTER */}
        <div className="p-3 border-t border-[#1e293b] bg-[#0e131b] flex items-center justify-between text-[10px] text-slate-500">
          <span>Click any template to instantiate on canvas</span>
          <button onClick={onClose} className="px-3 py-1 rounded-lg bg-[#161b22] text-slate-300 hover:text-white font-semibold">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
