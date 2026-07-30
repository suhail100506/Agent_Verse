import React, { useState } from 'react';
import { 
  Play, 
  Sparkles, 
  Search, 
  Bell, 
  ShieldCheck, 
  Layers, 
  ChevronRight, 
  Save, 
  Rocket,
  CheckCircle2, 
  FolderGit2,
  Sliders
} from 'lucide-react';

export default function Header({ 
  onRunWorkflow, 
  isRunning, 
  onOpenCommandPalette, 
  onOpenAiCopilot,
  onOpenTemplates,
  onSaveWorkflow,
  isSaved,
  nodeCount,
  edgeCount
}) {
  const [workspace, setWorkspace] = useState('Production');

  return (
    <header className="h-14 bg-[#252525]/95 backdrop-blur-xl border-b border-black/20 px-4 flex items-center justify-between shrink-0 z-30 select-none text-zinc-100 transition-all duration-300">
      {/* LEFT SECTION: Logo, Workspace Selector & Breadcrumbs */}
      <div className="flex items-center gap-4">
        {/* Brand Logo */}
        <div className="flex items-center gap-2 pr-4 border-r border-white/10">
          <div className="w-7 h-7 rounded-lg bg-zinc-100 flex items-center justify-center shadow-[0_0_15px_rgba(255,255,255,0.1)]">
            <ShieldCheck className="w-4 h-4 text-zinc-950" strokeWidth={2.5} />
          </div>
          <div className="flex flex-col">
            <span className="font-semibold text-xs tracking-tight text-white flex items-center gap-1.5">
              CYBERVERSE
            </span>
          </div>
        </div>

        {/* Workspace & Breadcrumb Navigation */}
        <div className="flex items-center gap-2 text-[13px] font-medium text-zinc-400">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-md hover:bg-white/5 transition-colors cursor-pointer group">
            <span className="text-zinc-300">{workspace}</span>
            <ChevronRight className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
          </div>

          <span className="text-zinc-600">/</span>

          <div className="flex items-center gap-2 px-2 py-1">
            <span className="text-zinc-200">Orchestration Flow</span>
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]"></span>
              Live
            </span>
          </div>
        </div>
      </div>

      {/* CENTER SECTION: Global Command Palette Search Bar */}
      <div className="hidden md:flex flex-1 justify-center max-w-md mx-4">
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center gap-3 px-3 py-1.5 rounded-lg bg-[#1E1E1E] border border-black/20 hover:border-white/10 hover:bg-[#333333] text-zinc-400 transition-all text-xs w-full justify-between group shadow-sm"
        >
          <div className="flex items-center gap-2">
            <Search className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
            <span>Search components, actions...</span>
          </div>
          <kbd className="px-1.5 py-0.5 rounded bg-[#2B2B2B] border border-black/20 text-[10px] font-mono text-zinc-400 font-medium">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* RIGHT SECTION: Controls, AI Copilot, Run, Deploy */}
      <div className="flex items-center gap-3">
        {/* Node Stats Badge */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 text-[11px] font-medium text-zinc-400">
          <Layers className="w-3.5 h-3.5 text-zinc-500" />
          <span>{nodeCount} Nodes</span>
        </div>

        {/* AI Copilot Button */}
        <button
          onClick={onOpenAiCopilot}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-white/5 text-zinc-300 hover:text-white transition-all text-xs font-medium group"
        >
          <Sparkles className="w-3.5 h-3.5 text-indigo-400 group-hover:text-indigo-300 transition-colors" />
          <span>Copilot</span>
        </button>

        {/* Templates Button */}
        <button
          onClick={onOpenTemplates}
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-white/5 text-zinc-300 hover:text-white transition-all text-xs font-medium"
        >
          <Sliders className="w-3.5 h-3.5 text-zinc-400" />
          <span>Templates</span>
        </button>

        {/* Save Button */}
        <button
          onClick={onSaveWorkflow}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg hover:bg-white/5 text-zinc-300 hover:text-white transition-all text-xs font-medium"
        >
          {isSaved ? (
            <>
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-emerald-400">Saved</span>
            </>
          ) : (
            <>
              <Save className="w-3.5 h-3.5 text-zinc-400" />
              <span>Save</span>
            </>
          )}
        </button>

        {/* Run Execution Button */}
        <button
          onClick={onRunWorkflow}
          disabled={isRunning}
          className={`flex items-center gap-2 px-4 py-1.5 rounded-lg font-medium text-xs transition-all ${
            isRunning 
              ? 'bg-amber-500/10 border border-amber-500/20 text-amber-400 cursor-wait'
              : 'bg-white text-zinc-950 hover:bg-zinc-200 shadow-[0_0_15px_rgba(255,255,255,0.1)] active:scale-[0.98]'
          }`}
        >
          <Play className={`w-3.5 h-3.5 fill-current ${isRunning ? 'animate-spin' : ''}`} />
          <span>{isRunning ? 'Running...' : 'Run'}</span>
        </button>

        {/* Deploy Button */}
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#333333] border border-black/20 hover:bg-[#3B3B3B] text-zinc-300 hover:text-white text-xs font-medium transition-all active:scale-[0.98]">
          <Rocket className="w-3.5 h-3.5" />
          <span>Deploy</span>
        </button>

        {/* Divider */}
        <div className="w-px h-4 bg-white/10 mx-1" />

        {/* Notifications & Profile */}
        <button className="p-1.5 rounded-lg hover:bg-white/5 text-zinc-400 hover:text-white transition-colors relative">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1.5 w-1.5 h-1.5 rounded-full bg-rose-500 border border-zinc-950"></span>
        </button>

        <div className="w-7 h-7 rounded-full bg-[#3B3B3B] border border-white/10 cursor-pointer overflow-hidden flex items-center justify-center hover:border-white/20 transition-colors">
          <img src="https://ui-avatars.com/api/?name=Admin&background=252525&color=fafafa" alt="Profile" className="w-full h-full object-cover" />
        </div>
      </div>
    </header>
  );
}
