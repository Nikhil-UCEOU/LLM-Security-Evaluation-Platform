import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import AttackResultsTable from '../components/tables/AttackResultsTable'
import BeforeAfterDiff from '../components/comparison/BeforeAfterDiff'
import { evaluationsApi } from '../api/evaluations'
import type { EvaluationRun } from '../types/evaluation'
import { ArrowLeft, RefreshCw } from 'lucide-react'

export default function Results() {
  const { runId } = useParams<{ runId?: string }>()
  const [run, setRun] = useState<EvaluationRun | null>(null)
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!runId) return
    setLoading(true)
    Promise.all([
      evaluationsApi.get(parseInt(runId)),
      evaluationsApi.getReport(parseInt(runId)),
    ])
      .then(([r, rep]) => { setRun(r); setReport(rep) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [runId])

  if (!runId) {
    return (
      <div className="flex-1 flex flex-col">
        <TopBar title="Results" subtitle="Select an evaluation to view results" />
        <div className="flex-1 p-6">
          <p className="text-gray-500 text-sm">Select a run from the <Link to="/" className="text-brand-500">Dashboard</Link>.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title={`Results — Run #${runId}`} subtitle={run ? `${run.provider} / ${run.model}` : ''} />
      <div className="flex-1 p-6 space-y-6">

        <Link to="/" className="inline-flex items-center gap-2 text-gray-500 hover:text-gray-300 text-sm">
          <ArrowLeft size={14} /> Back to Dashboard
        </Link>

        {loading && (
          <div className="flex items-center gap-2 text-gray-500">
            <RefreshCw size={14} className="animate-spin" /> Loading...
          </div>
        )}

        {run && (
          <>
            {/* Summary metrics */}
            <div className="grid grid-cols-4 gap-4">
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Global ISR</div>
                <div className={`text-3xl font-bold ${(run.global_isr || 0) > 0.5 ? 'text-red-400' : 'text-green-400'}`}>
                  {run.global_isr !== null ? `${(run.global_isr * 100).toFixed(1)}%` : '—'}
                </div>
              </div>
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Total Attacks</div>
                <div className="text-3xl font-bold text-white">{run.results.length}</div>
              </div>
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Unsafe</div>
                <div className="text-3xl font-bold text-red-400">
                  {run.results.filter((r) => r.isr_contribution > 0).length}
                </div>
              </div>
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-1">Critical</div>
                <div className="text-3xl font-bold text-red-500">
                  {run.results.filter((r) => r.severity === 'critical').length}
                </div>
              </div>
            </div>

            {/* Before/After Mitigation */}
            {report?.mitigation?.original_isr !== null && report?.mitigation?.original_isr !== undefined && (
              <div className="card">
                <h2 className="text-sm font-semibold text-gray-300 mb-4">Before vs After Mitigation</h2>
                <BeforeAfterDiff
                  originalIsr={report.mitigation.original_isr}
                  hardenedIsr={report.mitigation.hardened_isr}
                  improvementPct={report.mitigation.improvement_pct}
                  strategy={report.mitigation.strategy || 'auto'}
                />
              </div>
            )}

            {/* Results table */}
            <div className="card">
              <h2 className="text-sm font-semibold text-gray-300 mb-4">Attack Results</h2>
              <AttackResultsTable results={run.results} />
            </div>

            {/* RCA */}
            {report?.behavioral_analysis && (
              <div className="card">
                <h2 className="text-sm font-semibold text-gray-300 mb-4">Behavioral Analysis</h2>
                <p className="text-gray-400 text-sm">{report.behavioral_analysis}</p>
                {report.architectural_findings && (
                  <>
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mt-4 mb-2">Architectural Findings</h3>
                    <p className="text-gray-400 text-sm">{report.architectural_findings}</p>
                  </>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
