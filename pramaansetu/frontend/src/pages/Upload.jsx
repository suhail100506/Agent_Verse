import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, ArrowRight, Loader2, Sparkles, Building2 } from 'lucide-react';
import UploadDropzone from '../components/UploadDropzone';
import api from '../api/client';

export default function UploadPage() {
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleUploadSubmit = async () => {
    if (!file) return;
    setUploading(true);
    setError('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await api.post('/certificates/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      const { verification_id } = response.data;
      navigate(`/verification/${verification_id}`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed. Please try again.');
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8">
      {/* Title Header */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-brand-50 border border-brand-200 text-brand-700 text-xs font-mono font-bold">
          <Sparkles className="w-3.5 h-3.5 text-brand-600" />
          <span>India-First Forensic Certificate Engine</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-slate-900 font-mono">
          Certificate Authenticity Verification
        </h1>
        <p className="text-slate-600 text-sm max-w-2xl mx-auto leading-relaxed">
          Upload any degree, marksheet, government ID, or professional certification. PramaanSetu executes an 18-stage forensic pipeline inspecting layout, seals, signatures, EXIF metadata, and ELA tampering indicators.
        </p>
      </div>

      {/* Main Upload Box */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm space-y-6">
        <UploadDropzone onFileSelected={(f) => setFile(f)} isLoading={uploading} />

        {error && (
          <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs text-center font-semibold">
            {error}
          </div>
        )}

        <div className="flex justify-end pt-2">
          <button
            onClick={handleUploadSubmit}
            disabled={!file || uploading}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-8 py-3.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-sm transition-all shadow-md active:scale-95 disabled:opacity-40 disabled:pointer-events-none"
          >
            {uploading ? (
              <>
                <Loader2 className="w-5 h-5 animate-spin" />
                <span>Launching 18-Stage Pipeline...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-5 h-5" />
                <span>Initiate Verification Pipeline</span>
                <ArrowRight className="w-4 h-4 ml-1" />
              </>
            )}
          </button>
        </div>
      </div>

      {/* Institution Templates Supported Banner */}
      <div className="bg-white border border-slate-200 rounded-2xl p-5 space-y-3 shadow-2xs">
        <div className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-slate-500 font-bold">
          <Building2 className="w-4 h-4 text-brand-600" />
          <span>Pre-Seeded Institutional Template Libraries</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {["Anna University", "VTU Karnataka", "IIT Madras", "NIT Surathkal/Trichy", "CBSE Board", "UGC India", "Government of India"].map((inst) => (
            <span
              key={inst}
              className="px-3 py-1.5 rounded-lg bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold"
            >
              {inst}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
