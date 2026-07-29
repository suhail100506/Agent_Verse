import React, { useState } from 'react';
import { Sparkles, X, Wand2, ArrowRight, Loader2, Bot } from 'lucide-react';

export default function AiCopilotModal({ isOpen, onClose, onGenerateWorkflow }) {
  const [prompt, setPrompt] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const quickPrompts = [
    "Verify university degree certificates with PKI and ELA visual forensics",
    "Scan PE executables for malware signatures and lookup IP reputation on AbuseIPDB",
    "Audit documents for GDPR PII violations and dispatch alert to Telegram",
    "Monitor incoming webhooks, route through Master Orchestrator, and export PDF SOC report"
  ];

  const handleGenerate = async () => {
    if (!prompt) return;
    setLoading(true);
    await new Promise(r => setTimeout(r, 1200)); // Smooth AI generation delay
    onGenerateWorkflow(prompt);
    setLoading(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4 select-none">
      <div className="w-full max-w-lg bg-[#0b0f14] border border-indigo-500/30 rounded-2xl shadow-2xl overflow-hidden flex flex-col relative">
        {/* MODAL HEADER */}
        <div className="p-4 border-b border-[#1e293b] flex items-center justify-between bg-gradient-to-r from-indigo-950/40 via-[#0b0f14] to-cyan-950/40">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">CyberVerse AI Flow Copilot</h3>
              <p className="text-[10px] text-slate-400 font-medium">Natural Language Workflow Synthesizer</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* INPUT FORM */}
        <div className="p-4 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Describe the automation or security pipeline you want to build:
            </label>
            <textarea
              rows={4}
              placeholder="e.g. Ingest diploma PDF files, run OCR extraction, check PKI authenticity root, run ELA visual forensics, and trigger a Telegram alert if risk level is High..."
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              className="w-full bg-[#161b22] border border-[#1e293b] rounded-xl p-3 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            />
          </div>

          {/* QUICK PROMPT CHIPS */}
          <div className="space-y-1.5">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wider block">
              Suggested AI Prompts
            </span>
            <div className="flex flex-col gap-1.5">
              {quickPrompts.map((qp, idx) => (
                <button
                  key={idx}
                  onClick={() => setPrompt(qp)}
                  className="text-left p-2 rounded-xl bg-[#161b22] border border-[#1e293b] hover:border-indigo-500/40 text-[11px] text-slate-300 hover:text-indigo-300 transition-all flex items-center justify-between group"
                >
                  <span className="truncate pr-2">{qp}</span>
                  <ArrowRight className="w-3 h-3 text-slate-600 group-hover:text-indigo-400 shrink-0" />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* FOOTER ACTIONS */}
        <div className="p-4 border-t border-[#1e293b] bg-[#0e131b] flex items-center justify-between">
          <span className="text-[10px] text-slate-500 font-mono">Powered by CyberVerse LLM Orchestrator</span>
          <button
            disabled={loading || !prompt}
            onClick={handleGenerate}
            className="px-4 py-2 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 hover:from-indigo-500 hover:to-cyan-400 text-white font-bold text-xs shadow-lg shadow-indigo-600/30 flex items-center gap-1.5 transition-all disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wand2 className="w-4 h-4" />}
            <span>{loading ? "Synthesizing Pipeline..." : "Generate Workflow Graph"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
