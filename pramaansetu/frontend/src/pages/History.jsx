import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { History as HistoryIcon, Search, Filter, ExternalLink } from 'lucide-react';
import ClassificationBadge from '../components/ClassificationBadge';
import api from '../api/client';

export default function History() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState('');
  const [institutionQuery, setInstitutionQuery] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    const fetchHistory = async () => {
      setLoading(true);
      try {
        const response = await api.get('/history', {
          params: { page, limit: 15, status: statusFilter || undefined, institution: institutionQuery || undefined }
        });
        setRecords(response.data.records || []);
      } catch (err) {
        console.error("Failed to fetch history:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, [page, statusFilter, institutionQuery]);

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 flex items-center gap-2 font-mono">
            <HistoryIcon className="w-6 h-6 text-brand-600" />
            <span>Verification Audit History</span>
          </h1>
          <p className="text-xs text-slate-500 mt-1">Immutable append-only record of past certificate verification runs</p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-white border border-slate-200 rounded-2xl p-4 flex flex-col sm:flex-row items-center gap-3 shadow-xs">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3" />
          <input
            type="text"
            placeholder="Search by institution name..."
            value={institutionQuery}
            onChange={(e) => setInstitutionQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-xs font-mono focus:outline-none focus:border-brand-500 focus:bg-white"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3.5 py-2 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-xs font-mono font-semibold focus:outline-none focus:border-brand-500 focus:bg-white"
          >
            <option value="">All Statuses</option>
            <option value="Verified">Verified</option>
            <option value="Likely Genuine">Likely Genuine</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Likely Fake">Likely Fake</option>
            <option value="Fake">Fake</option>
            <option value="Manual Review Required">Manual Review Required</option>
          </select>
        </div>
      </div>

      {/* History Table */}
      <div className="bg-white border border-slate-200 rounded-2xl shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 font-mono text-slate-600 uppercase font-bold">
              <tr>
                <th className="px-4 py-3.5">Audit ID</th>
                <th className="px-4 py-3.5">Filename / Candidate</th>
                <th className="px-4 py-3.5">Cert Number</th>
                <th className="px-4 py-3.5">Institution</th>
                <th className="px-4 py-3.5">Score</th>
                <th className="px-4 py-3.5">Classification</th>
                <th className="px-4 py-3.5">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-400 font-mono font-medium">
                    Loading records...
                  </td>
                </tr>
              ) : records.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-400 font-mono font-medium">
                    No verification records found.
                  </td>
                </tr>
              ) : (
                records.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3.5 font-mono text-slate-500 font-semibold truncate max-w-[100px]">
                      {r.id.slice(-8)}
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="font-bold text-slate-900">{r.extracted_name || r.filename}</div>
                    </td>
                    <td className="px-4 py-3.5 font-mono font-bold text-amber-700">
                      {r.certificate_number || 'N/A'}
                    </td>
                    <td className="px-4 py-3.5 text-slate-800 font-medium">
                      {r.institution || 'Unknown'}
                    </td>
                    <td className="px-4 py-3.5 font-mono font-extrabold text-emerald-700">
                      {r.overall_score?.toFixed(1)}%
                    </td>
                    <td className="px-4 py-3.5">
                      <ClassificationBadge classification={r.classification} />
                    </td>
                    <td className="px-4 py-3.5">
                      <Link
                        to={`/verification/${r.id}/result`}
                        className="inline-flex items-center gap-1 text-xs font-mono font-bold text-brand-600 hover:text-brand-800 hover:underline"
                      >
                        <span>View</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
