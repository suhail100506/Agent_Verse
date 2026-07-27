import React, { useState } from 'react';
import { LayoutDashboard, AlertTriangle, ShieldCheck, Users, Search } from 'lucide-react';
import api from '../api/client';

export default function AdminDashboard() {
  const [duplicateQuery, setDuplicateQuery] = useState('AU12345678');
  const [duplicateResults, setDuplicateResults] = useState(null);
  const [searching, setSearching] = useState(false);

  const handleDuplicateSearch = async () => {
    if (!duplicateQuery) return;
    setSearching(true);
    try {
      const response = await api.get(`/history/duplicates/${encodeURIComponent(duplicateQuery)}`);
      setDuplicateResults(response.data);
    } catch (err) {
      console.error(err);
    } finally {
      setSearching(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900 flex items-center gap-2 font-mono">
          <LayoutDashboard className="w-6 h-6 text-brand-600" />
          <span>Admin Forensic Dashboard & Fraud Control</span>
        </h1>
        <p className="text-xs text-slate-500 mt-1">Cross-user duplicate alerts, template library registry & system metrics</p>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-brand-50 border border-brand-200 text-brand-600 flex items-center justify-center">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-xs font-mono font-bold text-slate-400 uppercase">Registered Templates</span>
            <span className="text-2xl font-extrabold font-mono text-slate-900">7 Standard Institutions</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center">
            <Users className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-xs font-mono font-bold text-slate-400 uppercase">Verification Engine</span>
            <span className="text-2xl font-extrabold font-mono text-emerald-700">18-Stage Active</span>
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-rose-50 border border-rose-200 text-rose-600 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <span className="block text-xs font-mono font-bold text-slate-400 uppercase">Fraud Detection Index</span>
            <span className="text-2xl font-extrabold font-mono text-rose-700">SHA256 & CertNo Hash</span>
          </div>
        </div>
      </div>

      {/* Duplicate Certificate Lookup Section */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 shadow-sm space-y-4">
        <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2 font-mono">
          <AlertTriangle className="w-5 h-5 text-amber-600" />
          <span>Cross-User Repeated Certificate Number Fraud Pattern Search</span>
        </h3>
        <p className="text-xs text-slate-500 font-medium">
          Enter a certificate number to check if it has been submitted across multiple user accounts (Memory Fraud Pattern Rule).
        </p>

        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
            <input
              type="text"
              value={duplicateQuery}
              onChange={(e) => setDuplicateQuery(e.target.value)}
              placeholder="e.g. AU12345678 or 1VT18CS001"
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-sm font-mono focus:outline-none focus:border-brand-500 focus:bg-white"
            />
          </div>
          <button
            onClick={handleDuplicateSearch}
            disabled={searching}
            className="px-6 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white text-sm font-mono font-bold shadow-xs transition-colors"
          >
            {searching ? "Searching..." : "Scan Fraud Log"}
          </button>
        </div>

        {duplicateResults && (
          <div className="mt-4 p-5 rounded-2xl bg-slate-50 border border-slate-200 space-y-2 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <span className="text-slate-700 font-bold">Cert Number: <strong className="text-amber-800">{duplicateResults.certificate_number}</strong></span>
              <span className={`px-2.5 py-1 rounded font-bold ${duplicateResults.is_fraud_risk ? 'bg-rose-100 text-rose-800 border border-rose-300' : 'bg-emerald-100 text-emerald-800'}`}>
                {duplicateResults.is_fraud_risk ? `Fraud Alert: ${duplicateResults.total_occurrences} Submissions Found` : 'Clean: Single Submission'}
              </span>
            </div>
            {duplicateResults.occurrences?.map((occ, i) => (
              <div key={i} className="flex justify-between py-1 text-slate-600">
                <span>User Email: {occ.uploaded_by_email}</span>
                <span>Institution: {occ.institution || 'N/A'}</span>
                <span>Verdict: {occ.classification}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
