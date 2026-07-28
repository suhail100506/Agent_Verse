import React, { useState } from 'react';
import { Download, Loader2 } from 'lucide-react';
import api from '../api/client';

export default function ReportPDFDownload({ verificationId }) {
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    if (!verificationId) return;
    setDownloading(true);
    try {
      const response = await api.get(`/reports/${verificationId}/download`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `Audit_Report_${verificationId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (err) {
      console.error("Failed to download PDF report:", err);
      alert("PDF Report download unavailable or processing.");
    } finally {
      setDownloading(false);
    }
  };

  return (
    <button
      onClick={handleDownload}
      disabled={downloading}
      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-sm transition-all shadow-sm active:scale-95 disabled:opacity-50"
    >
      {downloading ? (
        <Loader2 className="w-4 h-4 animate-spin text-white" />
      ) : (
        <Download className="w-4 h-4 text-white" />
      )}
      <span>{downloading ? "Downloading PDF..." : "Download PDF Report"}</span>
    </button>
  );
}
