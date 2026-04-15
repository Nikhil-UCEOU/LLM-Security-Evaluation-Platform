import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import client from '../api/client'
import {
  Shield, AlertTriangle, ChevronDown, ChevronUp, Info,
  CheckCircle, XCircle, AlertCircle, TrendingUp, BarChart3,
  ExternalLink, BookOpen, Target, Wrench, Search, RefreshCw,
  Activity, Lock, AlertOctagon,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
} from 'recharts'

// ── Types ──────────────────────────────────────────────────────────────────

interface OWASPRisk {
  risk_id: string
  name: string
  severity: string
  description: string
  mitigations: string[]
  examples: string[]
  cwe: string
  cvss_base: number
}

interface OWASPAssessment {
  risk_id: string
  risk_name: string
  severity: string
  success_rate: number
  attack_count: number
  successful_attacks: number
  risk_level: string
  mitigations: string[]
  evidence: string[]
  cvss_base: number
}

interface AnalysisData {
  failure_factors: any[]
  category_breakdown: Record<string, any>
  key_findings: string[]
  model_weaknesses: string[]
  vulnerability_profile: any
  priority_mitigations: any[]
  isr: number
  total_attacks: number
  successful_attacks: number
}

// ── Color helpers ─────────────────────────────────────────────────────────

const severityColor: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  none: '#6b7280',
}

const severityBg: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/30 text-red-400',
  high: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
  medium: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  low: 'bg-green-500/10 border-green-500/30 text-green-400',
}

const riskLevelIcon = (level: string) => {
  if (level === 'critical') return <XCircle className="w-4 h-4 text-red-400" />
  if (level === 'high') return <AlertTriangle className="w-4 h-4 text-orange-400" />
  if (level === 'medium') return <AlertCircle className="w-4 h-4 text-yellow-400" />
  return <CheckCircle className="w-4 h-4 text-green-400" />
}

// ── OWASPCard component ───────────────────────────────────────────────────

function OWASPCard({ risk, assessment }: { risk: OWASPRisk; assessment?: OWASPAssessment }) {
  const [expanded, setExpanded] = useState(false)
  const isr = assessment ? Math.round(assessment.success_rate * 100) : null
  const sev = risk.severity

  return (
    <div className={`border rounded-xl overflow-hidden`}
      style={{ background: 'rgba(255,255,255,0.02)', borderColor: `${severityColor[sev]}25` }}>
      <button
        className="w-full flex items-start justify-between p-4 hover:bg-white/03 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <div className="flex items-start gap-3 text-left flex-1">
          <span className={`inline-flex items-center justify-center px-2 py-0.5 rounded text-xs font-bold border flex-shrink-0 ${severityBg[sev]}`}>
            {risk.risk_id}
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-gray-200">{risk.name}</div>
            {!expanded && (
              <div className="text-xs text-gray-500 mt-0.5 truncate">{risk.description.slice(0, 80)}...</div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3 ml-3 flex-shrink-0">
          {assessment && assessment.attack_count > 0 ? (
            <div className="text-right">
              <div className="text-xs font-bold" style={{ color: severityColor[assessment.risk_level] || '#6b7280' }}>
                {isr}% ISR
              </div>
              <div className="text-[10px] text-gray-500">{assessment.successful_attacks}/{assessment.attack_count}</div>
            </div>
          ) : (
            <span className="text-[10px] text-gray-600 bg-white/04 px-2 py-0.5 rounded">
              CVSS {risk.cvss_base}
            </span>
          )}
          {assessment && riskLevelIcon(assessment.risk_level)}
          {expanded ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
          <div className="pt-3">
            <div className="text-xs text-gray-400 leading-relaxed">{risk.description}</div>
          </div>

          {/* ISR bar if tested */}
          {assessment && assessment.attack_count > 0 && (
            <div>
              <div className="flex justify-between text-[10px] text-gray-500 mb-1">
                <span>Attack Success Rate</span>
                <span className="font-bold" style={{ color: severityColor[assessment.risk_level] }}>{isr}%</span>
              </div>
              <div className="h-1.5 bg-white/06 rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all"
                  style={{ width: `${isr}%`, background: severityColor[assessment.risk_level] || '#e8003d' }} />
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Attack Patterns</div>
              <div className="space-y-1">
                {risk.examples?.slice(0, 3).map((ex, i) => (
                  <div key={i} className="text-[10px] text-gray-500 font-mono bg-white/03 px-2 py-0.5 rounded">
                    {ex.slice(0, 45)}{ex.length > 45 ? '…' : ''}
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Mitigations</div>
              <div className="space-y-1">
                {risk.mitigations?.slice(0, 3).map((m, i) => (
                  <div key={i} className="flex items-start gap-1 text-[10px] text-green-400/80">
                    <CheckCircle size={8} className="mt-0.5 flex-shrink-0" />
                    {m.slice(0, 50)}{m.length > 50 ? '…' : ''}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3 text-[10px] text-gray-600 pt-1">
            <span>CWE: {risk.cwe}</span>
            <span>CVSS: {risk.cvss_base}</span>
            <span className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase ${severityBg[sev]}`}>{sev}</span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────

export default function RiskDashboard() {
  const navigate = useNavigate()
  const [owaspRisks, setOwaspRisks] = useState<OWASPRisk[]>([])
  const [assessments, setAssessments] = useState<Record<string, OWASPAssessment>>({})
  const [recentAnalysis, setRecentAnalysis] = useState<AnalysisData | null>(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [activeTab, setActiveTab] = useState<'owasp' | 'analysis' | 'factors'>('owasp')

  const fetchData = async () => {
    setLoading(true)
    try {
      // Fetch OWASP risk definitions
      const { data: owaspData } = await client.get('/owasp/risks')
      setOwaspRisks(owaspData.risks || [])

      // Fetch recent evaluation results to assess risks
      const { data: evals } = await client.get('/evaluations/?limit=5')
      if (evals?.length > 0) {
        const latestRun = evals[0]

        // Fetch detailed results for assessment
        const { data: detailed } = await client.get(`/evaluations/${latestRun.run_id}`)
        const attackResults = detailed.results || []

        if (attackResults.length > 0) {
          // Get OWASP assessment
          const { data: assessData } = await client.post('/owasp/assess', {
            attack_results: attackResults.map((r: any) => ({
              classification: r.classification,
              category: r.attack_category || 'unknown',
              strategy: r.attack_strategy || 'unknown',
              tags: [],
              response_preview: r.response_text?.slice(0, 100) || '',
              owasp_risk: r.owasp_risk || 'LLM01',
            }))
          })
          setAssessments(assessData.assessments || {})

          // Fetch analysis
          try {
            const { data: analysisData } = await client.get(`/evaluations/${latestRun.run_id}/analysis`)
            setRecentAnalysis(analysisData)
          } catch {}
        }
      }
    } catch (err) {
      console.error('Risk dashboard load error:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const filteredRisks = owaspRisks.filter(r =>
    filter === 'all' ? true : r.severity === filter
  )

  // Radar chart data
  const radarData = owaspRisks.slice(0, 8).map(r => {
    const assessment = assessments[r.risk_id]
    return {
      risk: r.risk_id,
      value: assessment && assessment.attack_count > 0
        ? Math.round(assessment.success_rate * 100)
        : 0,
      fullMark: 100,
    }
  })

  // OWASP bar chart
  const barData = owaspRisks.map(r => {
    const assessment = assessments[r.risk_id]
    return {
      name: r.risk_id,
      isr: assessment && assessment.attack_count > 0
        ? Math.round(assessment.success_rate * 100)
        : 0,
      severity: r.severity,
    }
  })

  const totalTested = Object.values(assessments).reduce((s, a) => s + a.attack_count, 0)
  const totalSuccessful = Object.values(assessments).reduce((s, a) => s + a.successful_attacks, 0)
  const globalISR = totalTested > 0 ? Math.round(totalSuccessful / totalTested * 100) : 0
  const criticalRisks = Object.values(assessments).filter(a => a.risk_level === 'critical').length
  const highRisks = Object.values(assessments).filter(a => a.risk_level === 'high').length

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar title="Risk Dashboard" subtitle="OWASP LLM Top 10 risk assessment & analysis" />

      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <RefreshCw size={20} className="animate-spin text-pink-400 mr-3" />
            <span className="text-gray-400 text-sm">Loading risk assessment...</span>
          </div>
        ) : (
          <>
            {/* ── Summary Stats ─────────────────────────────────────── */}
            <div className="grid grid-cols-4 gap-4">
              {[
                { label: 'OWASP Risks Tracked', value: owaspRisks.length, icon: Shield, color: '#6366f1' },
                { label: 'Global Attack ISR', value: `${globalISR}%`, icon: Activity,
                  color: globalISR >= 60 ? '#ef4444' : globalISR >= 35 ? '#f97316' : globalISR >= 15 ? '#eab308' : '#22c55e' },
                { label: 'Critical Risk Categories', value: criticalRisks, icon: AlertOctagon, color: '#ef4444' },
                { label: 'High Risk Categories', value: highRisks, icon: AlertTriangle, color: '#f97316' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="rounded-xl border p-4"
                  style={{ background: `${color}08`, borderColor: `${color}20` }}>
                  <div className="flex items-center gap-2 mb-2">
                    <Icon size={14} style={{ color }} />
                    <span className="text-[11px] text-gray-500 uppercase tracking-wide">{label}</span>
                  </div>
                  <div className="text-2xl font-bold text-white">{value}</div>
                </div>
              ))}
            </div>

            {/* ── Tabs ───────────────────────────────────────────────── */}
            <div className="flex gap-1 border-b" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              {([
                { id: 'owasp', label: 'OWASP Top 10', icon: Shield },
                { id: 'analysis', label: 'Attack Analysis', icon: BarChart3 },
                { id: 'factors', label: 'Failure Factors', icon: Target },
              ] as const).map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className="flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all"
                  style={activeTab === tab.id ? {
                    borderBottomColor: '#e8003d',
                    color: '#f87171',
                  } : {
                    borderBottomColor: 'transparent',
                    color: '#6b7280',
                  }}>
                  <tab.icon size={12} />
                  {tab.label}
                </button>
              ))}
              <button
                onClick={fetchData}
                className="ml-auto flex items-center gap-1 px-3 py-2 text-xs text-gray-500 hover:text-gray-400">
                <RefreshCw size={11} /> Refresh
              </button>
            </div>

            {/* ── OWASP Tab ──────────────────────────────────────────── */}
            {activeTab === 'owasp' && (
              <div className="space-y-4">
                {/* Chart */}
                {totalTested > 0 && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="rounded-xl border p-4" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                      <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Attack Success Rate by OWASP Risk</div>
                      <ResponsiveContainer width="100%" height={180}>
                        <BarChart data={barData} barSize={18}>
                          <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 10 }} />
                          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                          <Tooltip
                            contentStyle={{ background: '#0d0e1a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8 }}
                            labelStyle={{ color: '#e2e8f0' }}
                            formatter={(v: any) => [`${v}%`, 'ISR']}
                          />
                          <Bar dataKey="isr">
                            {barData.map((entry, i) => (
                              <Cell key={i} fill={severityColor[entry.severity] || '#6b7280'} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>

                    <div className="rounded-xl border p-4" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                      <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Risk Coverage Radar</div>
                      <ResponsiveContainer width="100%" height={180}>
                        <RadarChart data={radarData}>
                          <PolarGrid stroke="rgba(255,255,255,0.06)" />
                          <PolarAngleAxis dataKey="risk" tick={{ fill: '#6b7280', fontSize: 10 }} />
                          <PolarRadiusAxis angle={90} domain={[0, 100]} tick={{ fill: '#4b5563', fontSize: 8 }} />
                          <Radar name="ISR" dataKey="value" stroke="#e8003d" fill="#e8003d" fillOpacity={0.2} />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}

                {/* Filter */}
                <div className="flex gap-2">
                  {(['all', 'critical', 'high', 'medium', 'low'] as const).map(f => (
                    <button key={f} onClick={() => setFilter(f)}
                      className="px-3 py-1 rounded-full text-xs font-semibold border transition-all capitalize"
                      style={filter === f ? {
                        background: `${f === 'all' ? '#6366f1' : severityColor[f]}20`,
                        borderColor: f === 'all' ? '#6366f1' : severityColor[f],
                        color: f === 'all' ? '#818cf8' : severityColor[f],
                      } : {
                        background: 'transparent',
                        borderColor: 'rgba(255,255,255,0.1)',
                        color: '#6b7280',
                      }}>
                      {f}
                    </button>
                  ))}
                </div>

                {/* Risk cards */}
                <div className="grid grid-cols-1 gap-3">
                  {filteredRisks.map(risk => (
                    <OWASPCard
                      key={risk.risk_id}
                      risk={risk}
                      assessment={assessments[risk.risk_id]}
                    />
                  ))}
                </div>
              </div>
            )}

            {/* ── Analysis Tab ───────────────────────────────────────── */}
            {activeTab === 'analysis' && (
              <div className="space-y-4">
                {recentAnalysis ? (
                  <>
                    {/* Vulnerability Profile */}
                    {recentAnalysis.vulnerability_profile && (
                      <div className="rounded-xl border p-5"
                        style={{
                          background: `${recentAnalysis.vulnerability_profile.color}08`,
                          borderColor: `${recentAnalysis.vulnerability_profile.color}30`,
                        }}>
                        <div className="flex items-center gap-3 mb-3">
                          <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                            style={{ background: `${recentAnalysis.vulnerability_profile.color}20` }}>
                            <Lock size={18} style={{ color: recentAnalysis.vulnerability_profile.color }} />
                          </div>
                          <div>
                            <div className="text-sm font-bold text-white">{recentAnalysis.vulnerability_profile.profile}</div>
                            <div className="text-xs text-gray-500">
                              ISR: {Math.round(recentAnalysis.isr * 100)}% — {recentAnalysis.successful_attacks}/{recentAnalysis.total_attacks} attacks succeeded
                            </div>
                          </div>
                        </div>
                        <div className="text-xs text-gray-400">{recentAnalysis.vulnerability_profile.description}</div>
                        <div className="mt-2 text-xs text-green-400">{recentAnalysis.vulnerability_profile.recommendation}</div>
                      </div>
                    )}

                    {/* Key Findings */}
                    {recentAnalysis.key_findings?.length > 0 && (
                      <div className="rounded-xl border p-4" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-1.5">
                          <Search size={11} /> Key Findings
                        </div>
                        <div className="space-y-2">
                          {recentAnalysis.key_findings.map((f, i) => (
                            <div key={i} className="flex items-start gap-2 text-xs text-gray-300">
                              <AlertOctagon size={10} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                              {f}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Category Breakdown */}
                    {recentAnalysis.category_breakdown && Object.keys(recentAnalysis.category_breakdown).length > 0 && (
                      <div className="rounded-xl border p-4" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">Attack Category Breakdown</div>
                        <div className="space-y-3">
                          {Object.entries(recentAnalysis.category_breakdown)
                            .sort((a, b) => b[1].isr - a[1].isr)
                            .map(([cat, stats]) => {
                              const isr = stats.isr || 0
                              const barColor = isr >= 0.6 ? '#ef4444' : isr >= 0.35 ? '#f97316' : isr >= 0.1 ? '#eab308' : '#22c55e'
                              return (
                                <div key={cat}>
                                  <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs text-gray-300 capitalize">{cat.replace(/_/g, ' ')}</span>
                                    <div className="flex items-center gap-2">
                                      <span className="text-[10px] text-gray-500">{stats.successful}/{stats.total}</span>
                                      <span className="text-xs font-bold" style={{ color: barColor }}>
                                        {Math.round(isr * 100)}%
                                      </span>
                                    </div>
                                  </div>
                                  <div className="h-1.5 bg-white/06 rounded-full overflow-hidden">
                                    <div className="h-full rounded-full" style={{ width: `${Math.round(isr * 100)}%`, background: barColor }} />
                                  </div>
                                  {stats.vulnerability && (
                                    <div className="text-[10px] text-gray-600 mt-1">{stats.vulnerability}</div>
                                  )}
                                </div>
                              )
                            })}
                        </div>
                      </div>
                    )}

                    {/* Priority Mitigations */}
                    {recentAnalysis.priority_mitigations?.length > 0 && (
                      <div className="rounded-xl border p-4" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3 flex items-center gap-1.5">
                          <Wrench size={11} /> Priority Mitigations
                        </div>
                        <div className="space-y-2">
                          {recentAnalysis.priority_mitigations.map((m, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 rounded-lg border"
                              style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.2)' }}>
                              <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0"
                                style={{ background: 'linear-gradient(135deg,#e8003d,#6366f1)' }}>
                                {i + 1}
                              </div>
                              <div className="flex-1">
                                <div className="text-xs text-gray-300">{m.mitigation}</div>
                                <div className="text-[10px] text-gray-500 mt-0.5">
                                  Addresses: {m.addresses} · {m.owasp}
                                </div>
                              </div>
                              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border capitalize ${severityBg[m.severity]}`}>
                                {m.severity}
                              </span>
                            </div>
                          ))}
                        </div>
                        <button
                          onClick={() => navigate('/mitigation')}
                          className="w-full mt-3 py-2.5 rounded-xl text-xs font-semibold text-white flex items-center justify-center gap-2 transition-all"
                          style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 12px rgba(232,0,61,0.2)' }}>
                          <Wrench size={12} /> Apply All Mitigations
                        </button>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center h-64 gap-4">
                    <BarChart3 size={32} className="text-gray-600" />
                    <div className="text-center">
                      <div className="text-sm font-semibold text-gray-400">No Analysis Data Yet</div>
                      <div className="text-xs text-gray-600 mt-1">Run an evaluation to see attack analysis here</div>
                    </div>
                    <button
                      onClick={() => navigate('/run')}
                      className="px-4 py-2 rounded-xl text-xs font-semibold text-white"
                      style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
                      Run Evaluation
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* ── Failure Factors Tab ────────────────────────────────── */}
            {activeTab === 'factors' && (
              <div className="space-y-4">
                {(recentAnalysis?.failure_factors?.length ?? 0) > 0 ? (
                  <>
                    {/* Model Weaknesses */}
                    {(recentAnalysis!.model_weaknesses?.length ?? 0) > 0 && (
                      <div className="rounded-xl border p-4" style={{ background: 'rgba(239,68,68,0.04)', borderColor: 'rgba(239,68,68,0.2)' }}>
                        <div className="text-xs font-semibold text-red-400 uppercase tracking-wide mb-3">Model Weaknesses Detected</div>
                        <div className="space-y-2">
                          {recentAnalysis!.model_weaknesses!.map((w, i) => (
                            <div key={i} className="flex items-start gap-2 text-xs text-red-300/80">
                              <XCircle size={10} className="text-red-400 mt-0.5 flex-shrink-0" />
                              {w}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Factor Cards */}
                    {recentAnalysis!.failure_factors!.map((f, i) => {
                      const c = severityColor[f.severity] || '#6b7280'
                      return (
                        <div key={i} className="rounded-xl border p-4"
                          style={{ background: `${c}06`, borderColor: `${c}25` }}>
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <div className="text-sm font-bold" style={{ color: c }}>{f.label}</div>
                              <div className="text-[10px] text-gray-500 mt-0.5">
                                {f.owasp} · triggered {f.frequency}x · {Math.round(f.success_rate * 100)}% success rate
                              </div>
                            </div>
                            <span className={`text-[10px] px-2 py-0.5 rounded border font-bold uppercase ${severityBg[f.severity]}`}>
                              {f.severity}
                            </span>
                          </div>

                          <div className="text-xs text-gray-400 mb-2">{f.description}</div>

                          <div className="h-1.5 bg-white/06 rounded-full mb-3">
                            <div className="h-full rounded-full"
                              style={{ width: `${Math.round(f.success_rate * 100)}%`, background: c }} />
                          </div>

                          <div className="grid grid-cols-2 gap-3 text-[11px]">
                            <div>
                              <div className="text-indigo-400 font-semibold mb-0.5">Root Cause</div>
                              <div className="text-gray-500">{f.cause}</div>
                            </div>
                            <div>
                              <div className="text-green-400 font-semibold mb-0.5">Mitigation</div>
                              <div className="text-gray-500">{f.mitigation}</div>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center h-64 gap-4">
                    <Target size={32} className="text-gray-600" />
                    <div className="text-center">
                      <div className="text-sm font-semibold text-gray-400">No Failure Factors Yet</div>
                      <div className="text-xs text-gray-600 mt-1">Run an evaluation to analyze failure patterns</div>
                    </div>
                    <button
                      onClick={() => navigate('/run')}
                      className="px-4 py-2 rounded-xl text-xs font-semibold text-white"
                      style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
                      Run Evaluation
                    </button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
