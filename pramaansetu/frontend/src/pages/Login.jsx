import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, Mail, Loader2, ArrowRight } from 'lucide-react';
import api from '../api/client';

export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await api.post('/auth/login', { email, password });
      const { access_token, refresh_token, user } = response.data;

      localStorage.setItem('pramaan_access_token', access_token);
      localStorage.setItem('pramaan_refresh_token', refresh_token);
      localStorage.setItem('pramaan_user', JSON.stringify(user));

      onLoginSuccess(user);
      navigate('/upload');
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed. Check email & password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[75vh] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-3xl border border-slate-200 shadow-sm">
        <div className="text-center">
          <div className="mx-auto w-14 h-14 rounded-2xl bg-brand-900 border border-brand-800 flex items-center justify-center text-white mb-4 shadow-md">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-slate-900 font-mono">
            Pramaan<span className="text-brand-600">Setu</span> Portal
          </h2>
          <p className="mt-2 text-xs text-slate-500 font-medium">
            Sign in to access AI-powered multi-stage certificate verification
          </p>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs text-center font-bold">
            {error}
          </div>
        )}

        <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-sm font-mono focus:outline-none focus:border-brand-500 focus:bg-white"
                placeholder="verifier@institution.ac.in"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-700 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 text-sm font-mono focus:outline-none focus:border-brand-500 focus:bg-white"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-sm transition-all shadow-xs active:scale-[0.98] disabled:opacity-50"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin text-white" /> : <span>Sign In to PramaanSetu</span>}
            {!loading && <ArrowRight className="w-4 h-4 text-white" />}
          </button>
        </form>

        <div className="text-center pt-2 border-t border-slate-100">
          <p className="text-xs text-slate-500">
            Need a new account?{' '}
            <Link to="/register" className="text-brand-600 hover:underline font-bold">
              Create User Account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
