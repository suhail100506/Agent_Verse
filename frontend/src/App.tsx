import { Routes, Route, Navigate } from 'react-router-dom'
import Navbar from './components/Navbar'
import FlowStudio from './pages/FlowStudio'
import AgentTester from './pages/AgentTester'
import Dashboard from './pages/Dashboard'
import Analyze from './pages/Analyze'
import Reports from './pages/Reports'
import ReportDetail from './pages/ReportDetail'

export default function App() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Routes>
        {/* Full-screen Visual Orchestration Flow Studio */}
        <Route path="/" element={<FlowStudio />} />
        
        {/* ALL 14 Specialized Agent Testing Suite (matches user screenshot) */}
        <Route path="/agent-testing" element={<AgentTester />} />
        
        {/* Standard dashboard, analytics & reporting routes */}
        <Route path="/dashboard" element={
          <>
            <Navbar />
            <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
              <Dashboard />
            </main>
          </>
        } />
        <Route path="/analyze" element={
          <>
            <Navbar />
            <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
              <Analyze />
            </main>
          </>
        } />
        <Route path="/reports" element={
          <>
            <Navbar />
            <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
              <Reports />
            </main>
          </>
        } />
        <Route path="/reports/:id" element={
          <>
            <Navbar />
            <main style={{ flex: 1, padding: '2rem', maxWidth: '1400px', margin: '0 auto', width: '100%' }}>
              <ReportDetail />
            </main>
          </>
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  )
}
