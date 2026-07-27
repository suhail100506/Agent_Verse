import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import UploadPage from './pages/Upload';
import VerificationStatus from './pages/VerificationStatus';
import ReportView from './pages/ReportView';
import History from './pages/History';
import AdminDashboard from './pages/AdminDashboard';

export default function App() {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const storedUser = localStorage.getItem('pramaan_user');
    const token = localStorage.getItem('pramaan_access_token');
    
    if (storedUser && token) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.clear();
      }
    } else {
      // Default demo user session
      const demoUser = { id: 'verifier_demo', email: 'verifier@pramaansetu.ac.in', role: 'verifier' };
      localStorage.setItem('pramaan_user', JSON.stringify(demoUser));
      setUser(demoUser);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('pramaan_access_token');
    localStorage.removeItem('pramaan_refresh_token');
    localStorage.removeItem('pramaan_user');
    setUser(null);
  };

  return (
    <Router>
      <Layout user={user} onLogout={handleLogout}>
        <Routes>
          <Route path="/login" element={<Login onLoginSuccess={(u) => setUser(u)} />} />
          <Route path="/register" element={<Register onLoginSuccess={(u) => setUser(u)} />} />
          
          <Route path="/upload" element={<UploadPage />} />
          <Route path="/verification/:id" element={<VerificationStatus />} />
          <Route path="/verification/:id/result" element={<ReportView />} />
          <Route path="/history" element={<History />} />
          <Route path="/admin" element={<AdminDashboard />} />

          <Route path="*" element={<Navigate to="/upload" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}
