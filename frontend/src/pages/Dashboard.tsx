import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useEvaluationStore } from '../store/evaluationStore'
import TopBar from '../components/layout/TopBar'
import RiskScoreChart from '../components/charts/RiskScoreChart'
import SeverityPieChart from '../components/charts/SeverityPieChart'
import { Zap, Shield, AlertTriangle, CheckCircle, ArrowRight } from 'lucide-react'

export default function Dashboard() {
  const { summaries, lastReport, fetchSummaries, loading } = useEvaluationStore()

  useEffect(() => { fetchSummaries() }, [])

  const totalRuns = summaries.length
  const avgIsr = summaries.length
    ? summaries.reduce((s, r) => s + (r.global_isr || 0), 0) / summaries.length
    : 0
  const criticalRuns = summaries.filter((s) => s.critical_count > 0).length

  const categoryData = lastReport
    ? Object.entries(lastReport.isr_by_category).map(([category, isr]) => ({ category, isr }))
    : []

  const severityData = lastReport?.severity_distribution || {}

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Dashboard" subtitle="CortexFlow AI Security Overview" />
      <div className="flex-1 p-6 space-y-6">

        {/* Stats row */}
        <div className="grid grid-cols-4 gap-4">
          <div className="card">
            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Total Evaluations</div>
            <div className="text-3xl font-bold text-white">{loading ? '—' : totalRuns}</div>
          </div>
          <div className="card">
            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Avg. ISR</div>
            <div className={`text-3xl font-bold ${avgIsr > 0.5 ? 'text-red-400' : avgIsr > 0.2 ? 'text-yellow-400' : 'text-green-400'}`}>
              {loading ? '—' : `${(avgIsr * 100).toFixed(1)}%`}
            </div>
          </div>
          <div className="card">
            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Critical Runs</div>
            <div className="text-3xl font-bold text-red-400">{loading ? '—' : criticalRuns}</div>
          </div>
          <div className="card">
            <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Last Run Status</div>
            <div className="text-3xl font-bold text-white">
              {summaries[0]?.status === 'completed' ? (
                <span className="text-green-400">✓</span>
              ) : summaries[0]?.status === 'failed' ? (
                <span className="text-red-400">✗</span>
              ) : '—'}
            </div>
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-2 gap-6">
          <div className="card">
            <h2 className="text-sm font-semibold text-gray-300 mb-4">ISR by Attack Category</h2>
            <RiskScoreChart data={categoryData} />
          </div>
          <div className="card">
            <h2 className="text-sm font-semibold text-gray-300 mb-4">Severity Distribution</h2>
            <SeverityPieChart data={severityData} />
          </div>
        </div>

        {/* Recent runs */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-300">Recent Evaluations</h2>
            <Link to="/results" className="text-brand-500 text-xs flex items-center gap-1 hover:text-brand-600">
              View all <ArrowRight size={12} />
            </Link>
          </div>
          <div className="space-y-2">
            {summaries.slice(0, 5).map((s) => (
              <Link
                key={s.run_id}
                to={`/results/${s.run_id}`}
                className="flex items-center justify-between p-3 rounded-lg bg-gray-800 hover:bg-gray-750 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-2 h-2 rounded-full ${s.status === 'completed' ? 'bg-green-400' : s.status === 'failed' ? 'bg-red-400' : 'bg-yellow-400'}`} />
                  <div>
                    <div className="text-sm font-medium text-gray-200">{s.provider} / {s.model}</div>
                    <div className="text-xs text-gray-500">{new Date(s.started_at).toLocaleString()}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <span className="text-gray-400">{s.total_attacks} attacks</span>
                  <span className={`font-semibold ${(s.global_isr || 0) > 0.5 ? 'text-red-400' : 'text-green-400'}`}>
                    ISR: {s.global_isr !== null ? `${(s.global_isr * 100).toFixed(1)}%` : '—'}
                  </span>
                </div>
              </Link>
            ))}
            {summaries.length === 0 && !loading && (
              <div className="text-center text-gray-500 py-8 text-sm">
                No evaluations yet.{' '}
                <Link to="/run" className="text-brand-500 hover:text-brand-600">Run your first evaluation →</Link>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}
