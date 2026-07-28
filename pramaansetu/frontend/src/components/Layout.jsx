import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, Upload, History, LayoutDashboard, LogOut } from 'lucide-react';

export default function Layout({ children, user, onLogout }) {
  const location = useLocation();

  const navItems = [
    { label: 'Upload & Verify', path: '/upload', icon: Upload, roles: ['applicant', 'verifier', 'admin'] },
    { label: 'Audit History', path: '/history', icon: History, roles: ['applicant', 'verifier', 'admin'] },
    { label: 'Admin Dashboard', path: '/admin', icon: LayoutDashboard, roles: ['admin'] },
  ];

  const userRole = user?.role || 'applicant';

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 font-sans">
      {/* Header Bar */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-50 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-xl bg-brand-900 border border-brand-800 flex items-center justify-center text-white shadow-md transition-transform group-hover:scale-105">
              <Shield className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-tight text-slate-900 font-mono">
                Fake Cert <span className="text-brand-600">Verification</span>
              </span>
              <span className="hidden sm:inline-block text-[10px] uppercase font-mono px-2 py-0.5 ml-2 rounded bg-slate-100 border border-slate-300 text-slate-600 font-semibold">
                Forensic Engine v1.0
              </span>
            </div>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center space-x-1">
            {navItems
              .filter((item) => item.roles.includes(userRole))
              .map((item) => {
                const Icon = item.icon;
                const active = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                      active
                        ? 'bg-brand-50 text-brand-700 border border-brand-200/80 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${active ? 'text-brand-600' : 'text-slate-500'}`} />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
          </nav>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-3">
            {user ? (
              <div className="flex items-center gap-3">
                <div className="hidden sm:flex flex-col text-right">
                  <span className="text-xs font-semibold text-slate-800">{user.email}</span>
                  <span className="text-[10px] font-mono uppercase font-bold text-brand-600 tracking-wider">
                    Role: {user.role}
                  </span>
                </div>
                <button
                  onClick={onLogout}
                  className="p-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-600 hover:text-rose-600 hover:bg-rose-50 hover:border-rose-200 transition-all"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <Link
                to="/login"
                className="px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-700 text-white text-sm font-semibold shadow-sm transition-all"
              >
                Sign In
              </Link>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-slate-200 py-6 text-center text-xs text-slate-500 font-mono">
        <p className="font-semibold text-slate-600">Fake Certificate Verification — AI-Powered Multi-Stage Certificate Verification Engine</p>
        <p className="mt-1">India-First Architecture: Anna University • VTU • IIT/NIT • CBSE • UGC • GoI</p>
      </footer>
    </div>
  );
}
