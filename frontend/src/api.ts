// api.ts — CyberVerse API client
import axios from 'axios'

// Connect directly to FastAPI backend on port 8000 to avoid Vite static dev-server 405 errors
const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

export const api = axios.create({ baseURL: BASE })

// Attach token from localStorage on each request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('cv_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Types
export interface SpecialistResult {
  specialist: string
  display_name: string
  success: boolean
  score: number
  risk_level: string
  confidence: number
  dashboard: Record<string, unknown>
  findings: string[]
  recommendations: string[]
  executive_summary: string
  error?: string
  duration_ms: number
}

export interface PlatformRisk {
  overall_score: number
  overall_risk: string
  confidence: number
  specialists_run: number
  specialists_succeeded: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  score_breakdown: Record<string, number>
}

export interface OrchestratorReport {
  report_id: string
  label?: string
  created_at: string
  status: string
  request_inputs: Record<string, unknown>
  platform_risk: PlatformRisk
  specialist_results: SpecialistResult[]
  all_findings: string[]
  all_recommendations: string[]
  executive_summary: string
  total_duration_ms: number
}

export interface ReportSummary {
  report_id: string
  label?: string
  created_at: string
  overall_risk: string
  overall_score: number
  specialists_run: number
  status: string
}

export interface SpecialistInfo {
  key: string
  display_name: string
  available: boolean
}

// API calls
export const login = async (username: string, password: string) => {
  const form = new FormData()
  form.append('username', username)
  form.append('password', password)
  const { data } = await api.post('/auth/token', form)
  localStorage.setItem('cv_token', data.access_token)
  return data
}

export const logout = () => localStorage.removeItem('cv_token')
export const isLoggedIn = () => !!localStorage.getItem('cv_token')

export const fetchSpecialists = (): Promise<SpecialistInfo[]> =>
  api.get('/specialists').then(r => r.data)

export const runAnalysis = (
  specialists: string[],
  inputs: Record<string, string>,
  label?: string
): Promise<OrchestratorReport> =>
  api.post('/analyze', { specialists, inputs, label }).then(r => r.data)

export const fetchReports = (limit = 20, offset = 0) =>
  api.get(`/reports?limit=${limit}&offset=${offset}`).then(r => r.data)

export const fetchReport = (id: string): Promise<OrchestratorReport> =>
  api.get(`/reports/${id}`).then(r => r.data)

export const deleteReport = (id: string) =>
  api.delete(`/reports/${id}`).then(r => r.data)

export const fetchHealth = () =>
  api.get('/health').then(r => r.data)
