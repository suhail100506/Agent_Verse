import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, AlertCircle, CheckCircle2 } from 'lucide-react';

export default function UploadDropzone({ onFileSelected, isLoading }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const inputRef = useRef(null);

  const validateAndSetFile = (file) => {
    setErrorMsg("");
    if (!file) return;

    const allowedTypes = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg'];
    if (!allowedTypes.includes(file.type) && !file.name.match(/\.(pdf|png|jpg|jpeg)$/i)) {
      setErrorMsg("Invalid file type. Please upload a PDF, PNG, or JPG certificate.");
      return;
    }

    if (file.size > 15 * 1024 * 1024) {
      setErrorMsg("File size exceeds 15MB maximum limit.");
      return;
    }

    setSelectedFile(file);
    if (onFileSelected) {
      onFileSelected(file);
    }
  };

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="w-full">
      <div
        className={`relative border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer ${
          dragActive
            ? 'border-brand-500 bg-brand-50/80 shadow-md'
            : selectedFile
            ? 'border-emerald-500 bg-emerald-50/60 shadow-sm'
            : 'border-slate-300 bg-white hover:border-brand-500 hover:bg-slate-50/80 shadow-sm'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pdf,.png,.jpg,.jpeg"
          className="hidden"
          onChange={(e) => e.target.files?.[0] && validateAndSetFile(e.target.files[0])}
        />

        {selectedFile ? (
          <div className="flex flex-col items-center justify-center py-4 space-y-3">
            <div className="w-14 h-14 rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center shadow-xs">
              <CheckCircle2 className="w-7 h-7" />
            </div>
            <div>
              <p className="font-bold text-slate-900 text-base">{selectedFile.name}</p>
              <p className="text-xs font-mono text-slate-500 mt-1">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for analysis
              </p>
            </div>
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setSelectedFile(null);
              }}
              className="text-xs font-semibold text-slate-500 hover:text-rose-600 underline pt-2"
            >
              Change document
            </button>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-6 space-y-3">
            <div className="w-14 h-14 rounded-full bg-brand-50 border border-brand-200 text-brand-600 flex items-center justify-center mb-1 shadow-xs">
              <UploadCloud className="w-7 h-7" />
            </div>
            <p className="text-base font-bold text-slate-800">
              Drag & Drop Certificate Document Here
            </p>
            <p className="text-xs text-slate-500 font-medium">
              Supports <span className="font-mono font-semibold text-slate-700">PDF, PNG, JPG</span> up to 15MB
            </p>
            <span className="inline-block mt-2 px-5 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-bold border border-slate-300 transition-colors shadow-2xs">
              Browse File System
            </span>
          </div>
        )}
      </div>

      {errorMsg && (
        <div className="mt-3 flex items-center gap-2 p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-medium">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  );
}
