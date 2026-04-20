import { useEffect, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import AttackResultsTable from '../components/tables/AttackResultsTable'
import { evaluationsApi } from '../api/evaluations'
import { useEvaluationStore } from '../store/evaluationStore'
import type { EvaluationRun } from '../types/evaluation'
import {
  ArrowLeft, RefreshCw, Shield, AlertTriangle, CheckCircle,
  TrendingUp, Zap, ChevronRight, Activity, Target,
  Wrench, BarChart3, ChevronDown, ChevronUp, FileText,
  AlertOctagon, Clock, X,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend, RadialBarChart, RadialBar,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316',
  medium: '#eab308', low: '#3b82f6', none: '#374151',
}

function getRisk(isr: number) {
  if (isr >= 0.6) return { label: 'CRITICAL', color: 'text-red-400',    bg: 'bg-red-950/40',    border: 'border-red-700',    hex: '#ef4444' }
  if (isr >= 0.4) return { label: 'HIGH',     color: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-700', hex: '#f97316' }
  if (isr >= 0.2) return { label: 'MEDIUM',   color: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-700', hex: '#eab308' }
  return               { label: 'LOW',      color: 'text-green-400',  bg: 'bg-green-950/40',  border: 'border-green-700',  hex: '#22c55e' }
}

// ── Inline Report Modal ───────────────────────────────────────────────────

function ReportModal({ runId, onClose }: { runId: number; onClose: () => void }) {
  const [run, setRun] = useState<EvaluationRun | null>(null)
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      evaluationsApi.get(runId),
      evaluationsApi.getReport(runId),
    ])
      .then(([r, rep]) => { setRun(r); setReport(rep) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [runId])

  if (loading) return (
    <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.85)' }}>
      <div className="flex items-center gap-3 text-gray-300">
        <RefreshCw size={18} className="animate-spin text-pink-400" />
        <span className="text-sm">Loading report...</span>
      </div>
    </div>
  )

  if (!run) return null

  const isr = run.global_isr || 0
  const risk = getRisk(isr)
  const unsafeCount = run.results.filter(r => r.isr_contribution > 0).length
  const criticalCount = run.results.filter(r => r.severity === 'critical').length
  const safeCount = run.results.length - unsafeCount
  const mitigation = report?.mitigation

  // Category breakdown
  const catData = run.results.reduce((acc, r) => {
    const cat = ((r as any).attack_category || 'unknown').replace(/_/g, ' ')
    if (!acc[cat]) acc[cat] = { safe: 0, unsafe: 0 }
    if (r.isr_contribution > 0) acc[cat].unsafe++ ; else acc[cat].safe++
    return acc
  }, {} as Record<string, { safe: number; unsafe: number }>)

  const categoryData = Object.entries(catData)
    .map(([name, v]) => ({ name, vulnerable: v.unsafe, blocked: v.safe, total: v.safe + v.unsafe }))
    .sort((a, b) => b.vulnerable - a.vulnerable).slice(0, 8)

  const sevData = run.results.reduce((acc, r) => {
    if (r.isr_contribution > 0) acc[r.severity] = (acc[r.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)
  const severityData = Object.entries(sevData)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      fill: SEVERITY_COLORS[name] || '#374151',
    }))

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto" style={{ background: 'rgba(0,0,0,0.9)' }}>
      <div className="min-h-full p-6 flex flex-col items-center">
        <div className="w-full max-w-4xl">
          {/* Report header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="text-[10px] text-gray-600 uppercase tracking-widest mb-1">Security Evaluation Report</div>
              <h1 className="text-xl font-black text-white">Run #{runId} — {run.provider}/{run.model}</h1>
              <div className="text-xs text-gray-500 mt-1 flex items-center gap-2">
                <Clock size={11} />
                {new Date(run.started_at).toLocaleString()}
              </div>
            </div>
            <button onClick={onClose}
              className="p-2 rounded-xl border border-white/10 text-gray-500 hover:text-gray-300 hover:bg-white/05 transition-all">
              <X size={16} />
            </button>
          </div>

          {/* Risk banner */}
          <div className={`rounded-2xl p-6 border mb-5 flex items-center justify-between ${risk.bg} ${risk.border}`}>
            <div>
              <div className={`text-4xl font-black mb-1 ${risk.color}`}>{risk.label} RISK</div>
              <div className="text-gray-400 text-sm">
                {unsafeCount} out of {run.results.length} attacks found a vulnerability
                {criticalCount > 0 && <span className="text-red-400 ml-2">· {criticalCount} critical severity</span>}
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {safeCount} attacks were successfully blocked by your model's defenses
              </div>
            </div>
            <div className="text-right">
              <div className={`text-5xl font-black ${risk.color}`}>{(isr * 100).toFixed(1)}%</div>
              <div className="text-xs text-gray-500 mt-1">Attack Success Rate</div>
              <div className="text-[10px] text-gray-600">lower is better</div>
            </div>
          </div>

          {/* Metric cards */}
          <div className="grid grid-cols-4 gap-4 mb-5">
            {[
              { label: 'Total Tests Run',     value: run.results.length,     sub: 'attacks attempted',    color: '#6366f1' },
              { label: 'Vulnerabilities',     value: unsafeCount,            sub: 'attacks that succeeded', color: unsafeCount > 0 ? '#ef4444' : '#22c55e' },
              { label: 'Critical Severity',   value: criticalCount,          sub: 'high-danger findings',  color: criticalCount > 0 ? '#ef4444' : '#22c55e' },
              { label: 'Attacks Blocked',     value: safeCount,              sub: 'defenses held',         color: '#22c55e' },
            ].map(({ label, value, sub, color }) => (
              <div key={label} className="rounded-2xl p-4 border text-center"
                style={{ background: `${color}08`, borderColor: `${color}25` }}>
                <div className="text-3xl font-black mb-1" style={{ color }}>{value}</div>
                <div className="text-xs font-semibold text-gray-300">{label}</div>
                <div className="text-[10px] text-gray-600 mt-0.5">{sub}</div>
              </div>
            ))}
          </div>

          {/* Charts */}
          {(categoryData.length > 0 || severityData.length > 0) && (
            <div className="grid grid-cols-2 gap-5 mb-5">
              {categoryData.length > 0 && (
                <div className="rounded-2xl border p-5"
                  style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <BarChart3 size={14} className="text-pink-400" />
                    <h3 className="text-sm font-semibold text-white">Results by Attack Type</h3>
                  </div>
                  <p className="text-[10px] text-gray-600 mb-4">Which categories of attacks succeeded vs. were blocked</p>
                  <ResponsiveContainer width="100%" height={Math.max(140, categoryData.length * 28)}>
                    <BarChart data={categoryData} layout="vertical" margin={{ left: 4, right: 12 }}>
                      <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9 }} />
                      <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 9 }} width={110} />
                      <Tooltip
                        contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                        formatter={(v: any, name: any) => [`${v}`, name === 'vulnerable' ? '🔴 Vulnerable' : '🟢 Blocked']}
                      />
                      <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }}
                        formatter={(v: any) => v === 'vulnerable' ? 'Vulnerable' : 'Blocked'} />
                      <Bar dataKey="vulnerable" name="vulnerable" fill="#ef4444" stackId="a" />
                      <Bar dataKey="blocked"    name="blocked"    fill="#22c55e" stackId="a" radius={[0,4,4,0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {severityData.length > 0 && (
                <div className="rounded-2xl border p-5"
                  style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <Target size={14} className="text-indigo-400" />
                    <h3 className="text-sm font-semibold text-white">Severity of Vulnerabilities</h3>
                  </div>
                  <p className="text-[10px] text-gray-600 mb-4">How dangerous each successful attack was</p>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={severityData} dataKey="value" nameKey="name"
                        cx="50%" cy="50%" outerRadius={65} innerRadius={32} paddingAngle={3}>
                        {severityData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                      </Pie>
                      <Tooltip
                        contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                        formatter={(v: any, name: any) => [`${v} attacks`, name]}
                      />
                      <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          )}

          {/* Before/After Mitigation */}
          {mitigation?.original_isr != null && (
            <div className="rounded-2xl border p-5 mb-5"
              style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.25)' }}>
              <div className="flex items-center gap-2 mb-4">
                <Wrench size={14} className="text-indigo-400" />
                <h3 className="text-sm font-semibold text-white">Before vs. After Security Fix</h3>
              </div>
              <div className="grid grid-cols-3 gap-5 items-center">
                <div className="text-center p-4 rounded-xl border border-red-800/30 bg-red-950/15">
                  <div className="text-[10px] text-gray-500 mb-2">BEFORE FIX</div>
                  <div className="text-4xl font-black text-red-400">{(mitigation.original_isr * 100).toFixed(1)}%</div>
                  <div className="text-[10px] text-red-400/70 mt-1">attack success rate</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-black text-green-400">
                    ↓ {mitigation.improvement_pct?.toFixed(0) || '—'}%
                  </div>
                  <div className="text-xs text-green-500 mt-1 font-semibold">improvement</div>
                  <div className="text-[10px] text-gray-600 mt-1">after applying security fixes</div>
                </div>
                <div className="text-center p-4 rounded-xl border border-green-800/30 bg-green-950/15">
                  <div className="text-[10px] text-gray-500 mb-2">AFTER FIX</div>
                  <div className="text-4xl font-black text-green-400">{(mitigation.hardened_isr * 100).toFixed(1)}%</div>
                  <div className="text-[10px] text-green-400/70 mt-1">attack success rate</div>
                </div>
              </div>
              <div className="mt-4 h-3 bg-white/05 rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-red-500/80 transition-all"
                  style={{ width: `${mitigation.original_isr * 100}%` }} />
              </div>
              <div className="mt-2 h-3 bg-white/05 rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-green-500/80 transition-all"
                  style={{ width: `${mitigation.hardened_isr * 100}%` }} />
              </div>
              <div className="flex justify-between text-[9px] text-gray-600 mt-1">
                <span>Before (red)</span><span>After (green)</span>
              </div>
            </div>
          )}

          {/* Root Cause Analysis */}
          {(report?.behavioral_analysis || report?.root_causes?.length > 0) && (
            <div className="rounded-2xl border p-5 mb-5"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp size={14} className="text-yellow-400" />
                <h3 className="text-sm font-semibold text-white">Why Attacks Succeeded — Root Cause Analysis</h3>
              </div>

              {report.behavioral_analysis && (
                <div className="mb-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">How the Model Behaved</div>
                  <p className="text-sm text-gray-400 leading-relaxed">{report.behavioral_analysis}</p>
                </div>
              )}

              {report.architectural_findings && (
                <div className="mb-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Structural Weaknesses Found</div>
                  <p className="text-sm text-gray-400 leading-relaxed">{report.architectural_findings}</p>
                </div>
              )}

              {Array.isArray(report.root_causes) && report.root_causes.length > 0 && (
                <div>
                  <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Root Causes</div>
                  <div className="space-y-2">
                    {report.root_causes.map((rc: any, i: number) => (
                      <div key={i} className="p-3 rounded-xl border border-yellow-900/30 bg-yellow-950/10">
                        <div className="text-xs font-semibold text-yellow-400 mb-1">{rc.category || rc.failure_mode}</div>
                        <div className="text-xs text-gray-400">{rc.description || rc.cause}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Detailed Attack Results Table */}
          <div className="rounded-2xl border mb-5"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
            <div className="flex items-center gap-2 p-5 pb-3">
              <Shield size={14} className="text-pink-400" />
              <h3 className="text-sm font-semibold text-white">Every Attack — Full Details</h3>
              <span className="text-[10px] text-gray-600">({run.results.length} attacks shown)</span>
            </div>
            <div className="px-5 pb-5">
              <AttackResultsTable results={run.results} />
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-3 pb-4">
            <button onClick={onClose}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-gray-400 border border-white/08 hover:bg-white/03 transition-all">
              <ArrowLeft size={13} /> Close Report
            </button>
            <Link
              to={`/mitigation/${runId}`}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white transition-all"
              style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
              <Wrench size={13} /> Fix Vulnerabilities
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Run List ──────────────────────────────────────────────────────────────

function RunList() {
  const navigate = useNavigate()
  const { summaries, loading, fetchSummaries } = useEvaluationStore()
  const [reportRunId, setReportRunId] = useState<number | null>(null)

  useEffect(() => { fetchSummaries() }, [])

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar title="Results" subtitle="All evaluation runs — click View Report for the full analysis" />
      <div className="flex-1 p-6 space-y-5 max-w-5xl mx-auto w-full">

        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-400">
            {summaries.length} evaluation{summaries.length !== 1 ? 's' : ''} completed
          </h2>
          <button onClick={fetchSummaries}
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors px-3 py-1.5 rounded-lg border"
            style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-sm text-gray-500 py-8 justify-center">
            <RefreshCw size={14} className="animate-spin" /> Loading results...
          </div>
        )}

        {!loading && summaries.length === 0 && (
          <div className="text-center py-20">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
              style={{ background: 'rgba(232,0,61,0.1)', border: '1px solid rgba(232,0,61,0.2)' }}>
              <Activity size={24} style={{ color: '#e8003d' }} />
            </div>
            <h3 className="text-lg font-bold text-white mb-2">No evaluations yet</h3>
            <p className="text-sm text-gray-500 mb-6">Run your first security evaluation to see results here.</p>
            <Link to="/run"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white"
              style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
              <Zap size={13} /> Start Evaluation
            </Link>
          </div>
        )}

        <div className="space-y-3">
          {summaries.map(s => {
            const isr = s.global_isr || 0
            const risk = getRisk(isr)
            return (
              <div key={s.run_id} className="rounded-2xl border transition-all hover:bg-white/02"
                style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-4 p-4">
                  {/* Risk indicator */}
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 border ${risk.bg} ${risk.border}`}>
                    {isr >= 0.4
                      ? <AlertTriangle size={16} className={risk.color} />
                      : <CheckCircle size={16} className={risk.color} />}
                  </div>

                  {/* Main info */}
                  <div className="flex-1 min-w-0 cursor-pointer" onClick={() => navigate(`/results/${s.run_id}`)}>
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-sm font-semibold text-white">{s.provider}/{s.model}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${risk.color} ${risk.bg} ${risk.border}`}>
                        {risk.label}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">{new Date(s.started_at).toLocaleString()}</div>
                  </div>

                  {/* Metrics */}
                  <div className="flex items-center gap-5 flex-shrink-0">
                    <div className="text-center">
                      <div className="text-[10px] text-gray-500 mb-0.5">Tests</div>
                      <div className="text-sm font-bold text-gray-300">{s.total_attacks}</div>
                    </div>
                    <div className="text-center">
                      <div className="text-[10px] text-gray-500 mb-0.5">Vulnerabilities</div>
                      <div className={`text-sm font-bold ${s.critical_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {s.critical_count}
                      </div>
                    </div>
                    <div className="text-center">
                      <div className="text-[10px] text-gray-500 mb-0.5">Attack Rate</div>
                      <div className={`text-sm font-bold ${risk.color}`}>
                        {isr > 0 ? `${(isr * 100).toFixed(1)}%` : '—'}
                      </div>
                    </div>

                    {/* Report button */}
                    <button
                      onClick={() => setReportRunId(s.run_id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-semibold text-white transition-all hover:opacity-90 flex-shrink-0"
                      style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', borderColor: 'rgba(99,102,241,0.4)' }}
                    >
                      <FileText size={11} /> View Report
                    </button>

                    <button
                      onClick={() => navigate(`/results/${s.run_id}`)}
                      className="p-1.5 text-gray-700 hover:text-gray-400 transition-colors"
                    >
                      <ChevronRight size={14} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Report Modal */}
      {reportRunId !== null && (
        <ReportModal runId={reportRunId} onClose={() => setReportRunId(null)} />
      )}
    </div>
  )
}

// ── Run Detail ────────────────────────────────────────────────────────────

function RunDetail({ runId }: { runId: string }) {
  const navigate = useNavigate()
  const [run, setRun] = useState<EvaluationRun | null>(null)
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [showRCA, setShowRCA] = useState(false)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      evaluationsApi.get(parseInt(runId)),
      evaluationsApi.getReport(parseInt(runId)),
    ])
      .then(([r, rep]) => { setRun(r); setReport(rep) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [runId])

  if (loading) return (
    <div className="flex-1 flex flex-col">
      <TopBar title={`Report — Run #${runId}`} subtitle="Loading..." />
      <div className="flex-1 flex items-center justify-center">
        <RefreshCw size={20} className="animate-spin text-pink-400" />
      </div>
    </div>
  )

  if (!run) return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Results" subtitle="Run not found" />
      <div className="flex-1 p-6">
        <Link to="/results" className="text-pink-400 text-sm flex items-center gap-1 hover:text-pink-300">
          <ArrowLeft size={13} /> Back to all results
        </Link>
      </div>
    </div>
  )

  const isr = run.global_isr || 0
  const risk = getRisk(isr)
  const unsafeCount = run.results.filter(r => r.isr_contribution > 0).length
  const criticalCount = run.results.filter(r => r.severity === 'critical').length
  const safeCount = run.results.length - unsafeCount
  const mitigation = report?.mitigation

  // Category chart data
  const catData = run.results.reduce((acc, r) => {
    const cat = ((r as any).attack_category || 'unknown').replace(/_/g, ' ')
    if (!acc[cat]) acc[cat] = { safe: 0, unsafe: 0 }
    if (r.isr_contribution > 0) acc[cat].unsafe++ ; else acc[cat].safe++
    return acc
  }, {} as Record<string, { safe: number; unsafe: number }>)

  const categoryData = Object.entries(catData)
    .map(([name, v]) => ({ name, vulnerable: v.unsafe, blocked: v.safe }))
    .sort((a, b) => b.vulnerable - a.vulnerable).slice(0, 8)

  const sevData = run.results.reduce((acc, r) => {
    if (r.isr_contribution > 0) acc[r.severity] = (acc[r.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)
  const severityData = Object.entries(sevData)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      value,
      fill: SEVERITY_COLORS[name] || '#374151',
    }))

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar
        title={`Report — Run #${runId}`}
        subtitle={`${run.provider}/${run.model} · ${new Date(run.started_at).toLocaleString()}`}
      />
      <div className="flex-1 p-6 space-y-5 max-w-6xl mx-auto w-full">

        <Link to="/results" className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={12} /> All Results
        </Link>

        {/* Risk banner */}
        <div className={`rounded-2xl p-6 border flex items-center justify-between ${risk.bg} ${risk.border}`}>
          <div>
            <div className={`text-3xl font-black mb-1 ${risk.color}`}>{risk.label} RISK</div>
            <div className="text-gray-400 text-sm">
              {unsafeCount} of {run.results.length} attacks found a vulnerability
              {criticalCount > 0 && <span className="text-red-400 ml-2">· {criticalCount} critical</span>}
            </div>
            <div className="text-xs text-gray-500 mt-1">{safeCount} attacks were successfully blocked</div>
          </div>
          <div className="text-right">
            <div className={`text-5xl font-black ${risk.color}`}>{(isr * 100).toFixed(1)}%</div>
            <div className="text-xs text-gray-500 mt-1">attack success rate</div>
          </div>
        </div>

        {/* Metric cards */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Tests Run',       value: run.results.length, color: '#6366f1' },
            { label: 'Vulnerabilities', value: unsafeCount,        color: unsafeCount > 0 ? '#ef4444' : '#22c55e' },
            { label: 'Critical',        value: criticalCount,      color: criticalCount > 0 ? '#ef4444' : '#22c55e' },
            { label: 'Blocked',         value: safeCount,          color: '#22c55e' },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-2xl p-4 border text-center"
              style={{ background: `${color}08`, borderColor: `${color}25` }}>
              <div className="text-3xl font-bold mb-1" style={{ color }}>{value}</div>
              <div className="text-xs text-gray-500">{label}</div>
            </div>
          ))}
        </div>

        {/* Charts */}
        {(categoryData.length > 0 || severityData.length > 0) && (
          <div className="grid grid-cols-2 gap-5">
            {categoryData.length > 0 && (
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-2 mb-1">
                  <BarChart3 size={14} className="text-pink-400" />
                  <h3 className="text-sm font-semibold text-white">Results by Attack Type</h3>
                </div>
                <p className="text-[10px] text-gray-600 mb-4">Which attack categories succeeded vs. were blocked</p>
                <ResponsiveContainer width="100%" height={Math.max(140, categoryData.length * 28)}>
                  <BarChart data={categoryData} layout="vertical" margin={{ left: 4, right: 12 }}>
                    <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9 }} />
                    <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 9 }} width={110} />
                    <Tooltip
                      contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                      formatter={(v: any, name: any) => [`${v}`, name === 'vulnerable' ? '🔴 Vulnerable' : '🟢 Blocked']}
                    />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }}
                      formatter={(v: any) => v === 'vulnerable' ? 'Vulnerable' : 'Blocked'} />
                    <Bar dataKey="vulnerable" name="vulnerable" fill="#ef4444" stackId="a" />
                    <Bar dataKey="blocked"    name="blocked"    fill="#22c55e" stackId="a" radius={[0,4,4,0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {severityData.length > 0 && (
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-2 mb-1">
                  <Target size={14} className="text-indigo-400" />
                  <h3 className="text-sm font-semibold text-white">Severity of Vulnerabilities</h3>
                </div>
                <p className="text-[10px] text-gray-600 mb-4">How dangerous each successful attack was</p>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name"
                      cx="50%" cy="50%" outerRadius={65} innerRadius={30} paddingAngle={3}>
                      {severityData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                      formatter={(v: any, name: any) => [`${v} attacks`, name]}
                    />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}

        {/* Before/After */}
        {mitigation?.original_isr != null && (
          <div className="rounded-2xl border p-5"
            style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.2)' }}>
            <div className="flex items-center gap-2 mb-4">
              <Wrench size={14} className="text-indigo-400" />
              <h3 className="text-sm font-semibold text-white">Before vs. After Security Fix</h3>
            </div>
            <div className="grid grid-cols-3 gap-5 items-center">
              <div className="text-center p-4 rounded-xl bg-red-950/15 border border-red-800/30">
                <div className="text-xs text-gray-500 mb-1">BEFORE FIX</div>
                <div className="text-4xl font-black text-red-400">{(mitigation.original_isr * 100).toFixed(1)}%</div>
                <div className="text-[10px] text-red-400/70 mt-1">attack success rate</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-black text-green-400">↓ {mitigation.improvement_pct?.toFixed(1) || '—'}%</div>
                <div className="text-xs text-green-500 mt-1">improvement</div>
              </div>
              <div className="text-center p-4 rounded-xl bg-green-950/15 border border-green-800/30">
                <div className="text-xs text-gray-500 mb-1">AFTER FIX</div>
                <div className="text-4xl font-black text-green-400">{(mitigation.hardened_isr * 100).toFixed(1)}%</div>
                <div className="text-[10px] text-green-400/70 mt-1">attack success rate</div>
              </div>
            </div>
          </div>
        )}

        {/* RCA */}
        {(report?.behavioral_analysis || report?.root_causes?.length) && (
          <div className="rounded-2xl border"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
            <button className="w-full flex items-center justify-between p-5 text-left"
              onClick={() => setShowRCA(s => !s)}>
              <div className="flex items-center gap-2">
                <TrendingUp size={14} className="text-yellow-400" />
                <h3 className="text-sm font-semibold text-white">Why Attacks Succeeded — Root Cause Analysis</h3>
              </div>
              {showRCA ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
            </button>
            {showRCA && (
              <div className="px-5 pb-5 space-y-4">
                {report.behavioral_analysis && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">How the Model Behaved</div>
                    <p className="text-sm text-gray-400 leading-relaxed">{report.behavioral_analysis}</p>
                  </div>
                )}
                {report.architectural_findings && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Structural Weaknesses</div>
                    <p className="text-sm text-gray-400 leading-relaxed">{report.architectural_findings}</p>
                  </div>
                )}
                {Array.isArray(report.root_causes) && report.root_causes.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Root Causes</div>
                    <div className="space-y-2">
                      {report.root_causes.map((rc: any, i: number) => (
                        <div key={i} className="p-3 rounded-xl border border-yellow-900/30 bg-yellow-950/10">
                          <div className="text-xs font-semibold text-yellow-400 mb-1">{rc.category || rc.failure_mode}</div>
                          <div className="text-xs text-gray-400">{rc.description || rc.cause}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Detailed results */}
        <div className="rounded-2xl border"
          style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="flex items-center gap-2 p-5 pb-3">
            <Shield size={14} className="text-pink-400" />
            <h3 className="text-sm font-semibold text-white">Every Attack — Full Details</h3>
          </div>
          <div className="p-5">
            <AttackResultsTable results={run.results} />
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pb-2">
          <button onClick={() => navigate(`/mitigation/${runId}`)}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white transition-all"
            style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
            <Wrench size={13} /> Fix Vulnerabilities
          </button>
          <Link to="/results"
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-gray-400 border border-white/08 hover:bg-white/03 transition-all">
            <ArrowLeft size={13} /> All Results
          </Link>
        </div>
      </div>
    </div>
  )
}

// ── Router ────────────────────────────────────────────────────────────────

export default function Results() {
  const { runId } = useParams<{ runId?: string }>()
  if (!runId) return <RunList />
  return <RunDetail runId={runId} />
}
