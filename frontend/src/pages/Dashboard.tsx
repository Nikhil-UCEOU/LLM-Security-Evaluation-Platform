import { useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useEvaluationStore } from '../store/evaluationStore'
import TopBar from '../components/layout/TopBar'
import RiskScoreChart from '../components/charts/RiskScoreChart'
import SeverityPieChart from '../components/charts/SeverityPieChart'
import {
  Zap, Shield, AlertTriangle, CheckCircle, ArrowRight,
  Target, TrendingUp, Activity, ChevronRight, Flame,
  Play, BarChart3, Brain, Wrench,
} from 'lucide-react'

const RISK_COLOR: Record<string, { text: string; dot: string }> = {
  critical: { text: 'text-red-400',    dot: 'bg-red-400' },
  high:     { text: 'text-orange-400', dot: 'bg-orange-400' },
  medium:   { text: 'text-yellow-400', dot: 'bg-yellow-400' },
  low:      { text: 'text-green-400',  dot: 'bg-green-400' },
}

function getRiskLevel(isr: number) {
  if (isr >= 0.6) return 'critical'
  if (isr >= 0.4) return 'high'
  if (isr >= 0.2) return 'medium'
  return 'low'
}

const WORKFLOW_STEPS = [
  { num: 1, to: '/run',        icon: Play,      title: 'Run Evaluation',   desc: 'Test your AI model for vulnerabilities',     color: '#e8003d' },
  { num: 2, to: '/results',    icon: BarChart3,  title: 'Review Results',   desc: 'See which attacks succeeded and why',         color: '#f59e0b' },
  { num: 3, to: '/mitigation', icon: Wrench,     title: 'Apply Fixes',      desc: 'Generate and apply security hardening',       color: '#6366f1' },
  { num: 4, to: '/benchmark',  icon: Target,     title: 'Benchmark Models', desc: 'Compare different LLMs side by side',         color: '#22c55e' },
]

export default function Dashboard() {
  const navigate = useNavigate()
  const { summaries, lastReport, fetchSummaries, loading } = useEvaluationStore()

  useEffect(() => { fetchSummaries() }, [])

  const totalRuns    = summaries.length
  const avgIsr       = totalRuns ? summaries.reduce((s, r) => s + (r.global_isr || 0), 0) / totalRuns : 0
  const criticalRuns = summaries.filter(s => (s.global_isr || 0) >= 0.6).length
  const safeRuns     = summaries.filter(s => (s.global_isr || 0) < 0.2).length

  const categoryData = lastReport
    ? Object.entries(lastReport.isr_by_category).map(([category, isr]) => ({ category, isr }))
    : []
  const severityData = lastReport?.severity_distribution || {}

  const isFirstTime = !loading && totalRuns === 0

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar title="Dashboard" subtitle="Security overview and platform guide" />

      <div className="flex-1 p-6 space-y-6 max-w-7xl mx-auto w-full">

        {/* ── Onboarding / First-time card ─────────────────────────────── */}
        {isFirstTime ? (
          <div className="rounded-2xl p-8 border relative overflow-hidden"
            style={{ background: 'linear-gradient(135deg, rgba(232,0,61,0.08), rgba(99,102,241,0.08))', borderColor: 'rgba(232,0,61,0.2)' }}>
            <div className="absolute top-0 right-0 w-64 h-64 rounded-full opacity-5"
              style={{ background: 'radial-gradient(circle, #e8003d, transparent)', transform: 'translate(30%, -30%)' }} />
            <div className="relative z-10">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                  style={{ background: 'rgba(232,0,61,0.15)' }}>
                  <Flame size={20} style={{ color: '#e8003d' }} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">Welcome to CortexFlow AI</h2>
                  <p className="text-sm text-gray-400">LLM Security Evaluation Platform</p>
                </div>
              </div>
              <p className="text-sm text-gray-400 mb-6 max-w-2xl">
                CortexFlow automatically tests your AI model for security vulnerabilities — prompt injection, jailbreaks, data leaks, and more.
                Start by running your first evaluation below.
              </p>
              <Link to="/run"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-sm font-bold text-white transition-all"
                style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 20px rgba(232,0,61,0.25)' }}>
                <Play size={14} /> Run Your First Evaluation
              </Link>
            </div>
          </div>
        ) : (
          /* ── Stats row ──────────────────────────────────────────────── */
          <div className="grid grid-cols-4 gap-4">
            {[
              {
                label: 'Total Tests Run',
                value: loading ? '—' : totalRuns,
                icon: Activity,
                color: '#6366f1',
                bg: 'rgba(99,102,241,0.1)',
              },
              {
                label: 'Avg. Vulnerability Rate',
                value: loading ? '—' : `${(avgIsr * 100).toFixed(1)}%`,
                icon: TrendingUp,
                color: avgIsr > 0.5 ? '#ef4444' : avgIsr > 0.2 ? '#f59e0b' : '#22c55e',
                bg: avgIsr > 0.5 ? 'rgba(239,68,68,0.1)' : avgIsr > 0.2 ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)',
              },
              {
                label: 'Critical Risk Runs',
                value: loading ? '—' : criticalRuns,
                icon: AlertTriangle,
                color: '#ef4444',
                bg: 'rgba(239,68,68,0.1)',
              },
              {
                label: 'Clean Runs',
                value: loading ? '—' : safeRuns,
                icon: CheckCircle,
                color: '#22c55e',
                bg: 'rgba(34,197,94,0.1)',
              },
            ].map(({ label, value, icon: Icon, color, bg }) => (
              <div key={label} className="rounded-2xl p-5 border"
                style={{ background: bg, borderColor: `${color}30` }}>
                <div className="flex items-center justify-between mb-3">
                  <div className="text-xs text-gray-500 font-medium">{label}</div>
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{ background: `${color}20` }}>
                    <Icon size={14} style={{ color }} />
                  </div>
                </div>
                <div className="text-3xl font-bold" style={{ color }}>{value}</div>
              </div>
            ))}
          </div>
        )}

        {/* ── Workflow Guide ────────────────────────────────────────────── */}
        <div className="rounded-2xl border p-5"
          style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-white">How It Works</h2>
            <span className="text-xs text-gray-500">Follow these steps</span>
          </div>
          <div className="grid grid-cols-4 gap-3">
            {WORKFLOW_STEPS.map((step, i) => {
              const Icon = step.icon
              return (
                <Link key={step.to} to={step.to}
                  className="group relative p-4 rounded-xl border transition-all hover:scale-[1.02]"
                  style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-white"
                      style={{ background: step.color }}>
                      {step.num}
                    </div>
                    <Icon size={13} style={{ color: step.color }} />
                  </div>
                  <div className="text-xs font-semibold text-white mb-1">{step.title}</div>
                  <div className="text-[10px] text-gray-500 leading-relaxed">{step.desc}</div>
                  {i < WORKFLOW_STEPS.length - 1 && (
                    <div className="absolute top-1/2 -right-2 transform -translate-y-1/2 z-10">
                      <ChevronRight size={12} className="text-gray-700" />
                    </div>
                  )}
                </Link>
              )
            })}
          </div>
        </div>

        {/* ── Charts (only if there's data) ────────────────────────────── */}
        {lastReport && (
          <div className="grid grid-cols-2 gap-6">
            <div className="rounded-2xl border p-5"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 size={14} className="text-pink-400" />
                <h2 className="text-sm font-semibold text-gray-300">Vulnerability Rate by Attack Type</h2>
              </div>
              <RiskScoreChart data={categoryData} />
            </div>
            <div className="rounded-2xl border p-5"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 mb-4">
                <Shield size={14} className="text-indigo-400" />
                <h2 className="text-sm font-semibold text-gray-300">Severity Breakdown</h2>
              </div>
              <SeverityPieChart data={severityData} />
            </div>
          </div>
        )}

        {/* ── Recent evaluations ────────────────────────────────────────── */}
        {totalRuns > 0 && (
          <div className="rounded-2xl border"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
            <div className="flex items-center justify-between p-5 pb-0 mb-4">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity size={14} className="text-pink-400" /> Recent Evaluations
              </h2>
              <Link to="/results" className="text-xs text-pink-400 flex items-center gap-1 hover:text-pink-300 transition-colors">
                View all <ArrowRight size={11} />
              </Link>
            </div>
            <div className="px-5 pb-5 space-y-2">
              {summaries.slice(0, 6).map(s => {
                const isr = s.global_isr || 0
                const risk = getRiskLevel(isr)
                const rc = RISK_COLOR[risk]
                return (
                  <Link key={s.run_id} to={`/results/${s.run_id}`}
                    className="flex items-center gap-4 p-3.5 rounded-xl border transition-all hover:bg-white/03 group"
                    style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${rc.dot}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-200">{s.provider}</span>
                        <span className="text-gray-600">/</span>
                        <span className="text-sm text-gray-400">{s.model}</span>
                      </div>
                      <div className="text-xs text-gray-600 mt-0.5">{new Date(s.started_at).toLocaleString()}</div>
                    </div>
                    <div className="flex items-center gap-4 flex-shrink-0">
                      <div className="text-center">
                        <div className="text-xs text-gray-500">Attacks</div>
                        <div className="text-sm font-medium text-gray-300">{s.total_attacks}</div>
                      </div>
                      <div className="text-center">
                        <div className="text-xs text-gray-500">ISR</div>
                        <div className={`text-sm font-bold ${rc.text}`}>
                          {isr > 0 ? `${(isr * 100).toFixed(1)}%` : '—'}
                        </div>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${rc.text}`}
                        style={{ background: `${rc.dot.includes('red') ? 'rgba(239,68,68' : rc.dot.includes('orange') ? 'rgba(249,115,22' : rc.dot.includes('yellow') ? 'rgba(234,179,8' : 'rgba(34,197,94'}, 0.1)`, borderColor: 'currentcolor' }}>
                        {risk}
                      </span>
                      <ChevronRight size={12} className="text-gray-700 group-hover:text-gray-500 transition-colors" />
                    </div>
                  </Link>
                )
              })}
            </div>
          </div>
        )}

        {/* ── Quick Actions ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { to: '/run', icon: Zap, label: 'Start New Evaluation', desc: 'Test a model now', color: '#e8003d' },
            { to: '/attacks', icon: Shield, label: 'Browse Attack Library', desc: 'View all test cases', color: '#6366f1' },
            { to: '/learning', icon: Brain, label: 'View Intelligence', desc: 'See what the system learned', color: '#f59e0b' },
          ].map(({ to, icon: Icon, label, desc, color }) => (
            <Link key={to} to={to}
              className="flex items-center gap-4 p-4 rounded-2xl border transition-all hover:scale-[1.01] group"
              style={{ background: `${color}08`, borderColor: `${color}20` }}>
              <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ background: `${color}20` }}>
                <Icon size={18} style={{ color }} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-white">{label}</div>
                <div className="text-xs text-gray-500">{desc}</div>
              </div>
              <ArrowRight size={14} className="text-gray-600 group-hover:text-gray-400 transition-colors flex-shrink-0" />
            </Link>
          ))}
        </div>

      </div>
    </div>
  )
}
