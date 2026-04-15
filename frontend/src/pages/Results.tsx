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
  Wrench, BarChart3, ChevronDown, ChevronUp,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316',
  medium: '#eab308', low: '#3b82f6', none: '#374151',
}

const CLASSIFICATION_STYLE: Record<string, { text: string; bg: string; border: string; label: string }> = {
  unsafe:  { text: 'text-red-400',    bg: 'bg-red-950/30',    border: 'border-red-800',    label: 'UNSAFE' },
  partial: { text: 'text-orange-400', bg: 'bg-orange-950/30', border: 'border-orange-800', label: 'PARTIAL' },
  safe:    { text: 'text-green-400',  bg: 'bg-green-950/30',  border: 'border-green-800',  label: 'SAFE' },
  unknown: { text: 'text-gray-400',   bg: 'bg-gray-800/30',   border: 'border-gray-700',   label: 'UNKNOWN' },
}

function getRisk(isr: number) {
  if (isr >= 0.6) return { label: 'CRITICAL', color: 'text-red-400',    bg: 'bg-red-950/40',    border: 'border-red-700' }
  if (isr >= 0.4) return { label: 'HIGH',     color: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-700' }
  if (isr >= 0.2) return { label: 'MEDIUM',   color: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-700' }
  return               { label: 'LOW',      color: 'text-green-400',  bg: 'bg-green-950/40',  border: 'border-green-700' }
}

// ── Run list (no runId selected) ──────────────────────────────────────────

function RunList() {
  const navigate = useNavigate()
  const { summaries, loading, fetchSummaries } = useEvaluationStore()

  useEffect(() => { fetchSummaries() }, [])

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar title="Results" subtitle="All evaluation runs and security findings" />
      <div className="flex-1 p-6 space-y-5 max-w-5xl mx-auto w-full">

        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-400">{summaries.length} evaluation{summaries.length !== 1 ? 's' : ''} completed</h2>
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
              <button key={s.run_id} onClick={() => navigate(`/results/${s.run_id}`)}
                className="w-full text-left p-4 rounded-2xl border transition-all hover:bg-white/02 group"
                style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-4">
                  {/* Risk indicator */}
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 border ${risk.bg} ${risk.border}`}>
                    {isr >= 0.4
                      ? <AlertTriangle size={16} className={risk.color} />
                      : <CheckCircle size={16} className={risk.color} />}
                  </div>

                  {/* Main info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-sm font-semibold text-white">{s.provider}/{s.model}</span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${risk.color} ${risk.bg} ${risk.border}`}>
                        {risk.label}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500">{new Date(s.started_at).toLocaleString()}</div>
                  </div>

                  {/* Metrics */}
                  <div className="flex items-center gap-6 flex-shrink-0">
                    <div className="text-center">
                      <div className="text-xs text-gray-500 mb-0.5">Attacks</div>
                      <div className="text-sm font-bold text-gray-300">{s.total_attacks}</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xs text-gray-500 mb-0.5">Vulnerabilities</div>
                      <div className={`text-sm font-bold ${s.critical_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {s.critical_count}
                      </div>
                    </div>
                    <div className="text-center">
                      <div className="text-xs text-gray-500 mb-0.5">ISR</div>
                      <div className={`text-sm font-bold ${risk.color}`}>
                        {isr > 0 ? `${(isr * 100).toFixed(1)}%` : '—'}
                      </div>
                    </div>
                    <ChevronRight size={14} className="text-gray-700 group-hover:text-gray-400 transition-colors" />
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      </div>
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
      <TopBar title={`Results — Run #${runId}`} subtitle="Loading..." />
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

  // Category breakdown chart data
  const catData = run.results.reduce((acc, r) => {
    const cat = (r as any).attack_category || 'unknown'
    if (!acc[cat]) acc[cat] = { safe: 0, unsafe: 0 }
    if (r.isr_contribution > 0) acc[cat].unsafe++ ; else acc[cat].safe++
    return acc
  }, {} as Record<string, { safe: number; unsafe: number }>)

  const categoryChartData = Object.entries(catData).map(([name, v]) => ({
    name: name.replace(/_/g, ' '),
    unsafe: v.unsafe, safe: v.safe,
    total: v.safe + v.unsafe,
  })).sort((a, b) => b.unsafe - a.unsafe).slice(0, 8)

  const sevData = run.results.reduce((acc, r) => {
    acc[r.severity] = (acc[r.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)
  const severityChartData = Object.entries(sevData)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value, fill: SEVERITY_COLORS[name] || '#374151' }))

  const mitigation = report?.mitigation

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar
        title={`Run #${runId} — ${run.provider}/${run.model}`}
        subtitle={new Date(run.started_at).toLocaleString()}
      />
      <div className="flex-1 p-6 space-y-5 max-w-6xl mx-auto w-full">

        {/* Back */}
        <Link to="/results" className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors">
          <ArrowLeft size={12} /> All Results
        </Link>

        {/* Risk banner */}
        <div className={`rounded-2xl p-5 border flex items-center justify-between ${risk.bg} ${risk.border}`}>
          <div className="flex items-center gap-4">
            <div className={`text-3xl font-black ${risk.color}`}>{risk.label}</div>
            <div className="text-gray-400 text-sm">
              {unsafeCount} of {run.results.length} attacks succeeded
              {criticalCount > 0 && <span className="text-red-400 ml-2">· {criticalCount} critical</span>}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className={`text-4xl font-black ${risk.color}`}>{(isr * 100).toFixed(1)}%</div>
            <div className="text-xs text-gray-500">vulnerability<br/>rate</div>
          </div>
        </div>

        {/* Metric cards */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Tests', value: run.results.length, color: '#6366f1' },
            { label: 'Vulnerabilities', value: unsafeCount, color: unsafeCount > 0 ? '#ef4444' : '#22c55e' },
            { label: 'Critical', value: criticalCount, color: criticalCount > 0 ? '#ef4444' : '#22c55e' },
            { label: 'Defended', value: run.results.length - unsafeCount, color: '#22c55e' },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-2xl p-4 border text-center"
              style={{ background: `${color}08`, borderColor: `${color}25` }}>
              <div className="text-xs text-gray-500 mb-2">{label}</div>
              <div className="text-3xl font-bold" style={{ color }}>{value}</div>
            </div>
          ))}
        </div>

        {/* Charts row */}
        <div className="grid grid-cols-2 gap-5">
          {categoryChartData.length > 0 && (
            <div className="rounded-2xl border p-5"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 size={14} className="text-pink-400" />
                <h3 className="text-sm font-semibold text-gray-300">Results by Attack Type</h3>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={categoryChartData} margin={{ left: 0, right: 8 }}>
                  <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 9 }} angle={-20} textAnchor="end" height={40} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="unsafe" stackId="a" fill="#e8003d" name="Vulnerable" radius={[0,0,0,0]} />
                  <Bar dataKey="safe" stackId="a" fill="#374151" name="Defended" radius={[4,4,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          {severityChartData.length > 0 && (
            <div className="rounded-2xl border p-5"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-4">
                <Target size={14} className="text-indigo-400" />
                <h3 className="text-sm font-semibold text-gray-300">Severity Distribution</h3>
              </div>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={severityChartData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label={({ name, value }) => `${name}: ${value}`}
                    labelLine={{ stroke: '#374151' }}>
                    {severityChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Before/After Mitigation */}
        {mitigation?.original_isr != null && (
          <div className="rounded-2xl border p-5"
            style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.2)' }}>
            <div className="flex items-center gap-2 mb-4">
              <Wrench size={14} className="text-indigo-400" />
              <h3 className="text-sm font-semibold text-gray-300">Before vs. After Security Fix</h3>
            </div>
            <div className="grid grid-cols-3 gap-5 items-center">
              <div className="text-center">
                <div className="text-xs text-gray-500 mb-1">Before Fix</div>
                <div className="text-4xl font-black text-red-400">{(mitigation.original_isr * 100).toFixed(1)}%</div>
                <div className="text-xs text-gray-600 mt-1">vulnerability rate</div>
              </div>
              <div className="text-center">
                <div className="text-4xl font-black text-green-400">
                  -{mitigation.improvement_pct?.toFixed(1) || '—'}%
                </div>
                <div className="text-xs text-green-600 mt-1">improvement</div>
              </div>
              <div className="text-center">
                <div className="text-xs text-gray-500 mb-1">After Fix</div>
                <div className="text-4xl font-black text-green-400">{(mitigation.hardened_isr * 100).toFixed(1)}%</div>
                <div className="text-xs text-gray-600 mt-1">residual rate</div>
              </div>
            </div>
            <div className="mt-4 flex gap-3">
              <div className="flex-1 h-3 rounded-full overflow-hidden bg-white/05">
                <div className="h-full rounded-full bg-red-500 transition-all"
                  style={{ width: `${mitigation.original_isr * 100}%` }} />
              </div>
            </div>
            <div className="mt-4">
              <button onClick={() => navigate(`/mitigation?runId=${runId}`)}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-400 hover:text-indigo-300 transition-colors">
                Open Mitigation Lab <ChevronRight size={11} />
              </button>
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
                <h3 className="text-sm font-semibold text-gray-300">Root Cause Analysis</h3>
              </div>
              {showRCA ? <ChevronUp size={14} className="text-gray-500" /> : <ChevronDown size={14} className="text-gray-500" />}
            </button>
            {showRCA && (
              <div className="px-5 pb-5 space-y-4">
                {report.behavioral_analysis && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Behavioral Analysis</div>
                    <p className="text-sm text-gray-400 leading-relaxed">{report.behavioral_analysis}</p>
                  </div>
                )}
                {report.architectural_findings && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Architectural Findings</div>
                    <p className="text-sm text-gray-400 leading-relaxed">{report.architectural_findings}</p>
                  </div>
                )}
                {Array.isArray(report.root_causes) && report.root_causes.length > 0 && (
                  <div>
                    <div className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Root Causes</div>
                    <div className="space-y-2">
                      {report.root_causes.map((rc: any, i: number) => (
                        <div key={i} className="p-3 rounded-xl border border-yellow-900/30 bg-yellow-950/15">
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

        {/* Attack results table */}
        <div className="rounded-2xl border"
          style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="flex items-center gap-2 p-5 pb-0">
            <Shield size={14} className="text-pink-400" />
            <h3 className="text-sm font-semibold text-gray-300">Detailed Attack Results</h3>
          </div>
          <div className="p-5">
            <AttackResultsTable results={run.results} />
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-3 pb-2">
          <button onClick={() => navigate(`/mitigation?runId=${runId}`)}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white transition-all"
            style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
            <Wrench size={13} /> Open Mitigation Lab
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
