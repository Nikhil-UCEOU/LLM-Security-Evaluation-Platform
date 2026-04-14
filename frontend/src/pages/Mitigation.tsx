import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import client from '../api/client'
import toast from 'react-hot-toast'
import {
  Shield, Zap, ChevronRight, ArrowLeft, Loader, RefreshCw,
  CheckCircle, AlertTriangle, TrendingDown, TrendingUp,
  Layers, Play, RotateCcw, History, ChevronDown, ChevronUp,
  Target, Lock, FileText, Award, Minus,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface MitigationStep {
  priority: number
  technique_id: string
  technique_name: string
  layer: string
  description: string
  implementation: string
  prompt_instruction: string
  estimated_effectiveness: number
  complexity: string
  addresses_failures: string[]
}

interface MitigationPlan {
  plan_id: string
  run_id: number
  original_isr: number
  total_failures: number
  failure_modes_detected: string[]
  steps: MitigationStep[]
  hardened_prompt: string
  guardrails: any[]
  estimated_residual_isr: number
  estimated_mes: number
  confidence: number
  priority_recommendation: string
}

interface ComparisonReport {
  original_isr: number
  hardened_isr: number
  isr_delta: number
  isr_improvement_pct: number
  original_dls: number
  hardened_dls: number
  dls_delta: number
  original_idi: number
  hardened_idi: number
  idi_delta: number
  mes: number
  grade: string
  summary: string
  failure_modes_detected: string[]
  priority_recommendation: string
  mitigation_steps_count: number
}

interface ApplyResult {
  run_id: number
  hardened_prompt: string
  active_techniques: string[]
  guardrails: any[]
  estimated_mes: number
  message: string
}

interface HistoryEntry {
  run_id: number
  plan_id: string
  timestamp: string
  original_isr: number
  hardened_isr: number
  mes: number
  grade: string
  techniques_count: number
}

// ── Helpers ────────────────────────────────────────────────────────────────

const LAYER_COLORS: Record<string, string> = {
  prompt:       'bg-blue-950/40 text-blue-300 border-blue-800/50',
  input:        'bg-purple-950/40 text-purple-300 border-purple-800/50',
  context:      'bg-cyan-950/40 text-cyan-300 border-cyan-800/50',
  output:       'bg-amber-950/40 text-amber-300 border-amber-800/50',
  tool:         'bg-orange-950/40 text-orange-300 border-orange-800/50',
  architecture: 'bg-gray-800/60 text-gray-300 border-gray-700',
}

const GRADE_COLORS: Record<string, string> = {
  A: 'text-emerald-400 border-emerald-700 bg-emerald-950/40',
  B: 'text-green-400 border-green-700 bg-green-950/40',
  C: 'text-yellow-400 border-yellow-700 bg-yellow-950/40',
  D: 'text-orange-400 border-orange-700 bg-orange-950/40',
  F: 'text-red-400 border-red-700 bg-red-950/40',
}

const COMPLEXITY_COLOR: Record<string, string> = {
  low:    'text-emerald-400',
  medium: 'text-yellow-400',
  high:   'text-red-400',
}

function LayerBadge({ layer }: { layer: string }) {
  const cls = LAYER_COLORS[layer] || LAYER_COLORS.architecture
  return (
    <span className={`text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${cls}`}>
      {layer}
    </span>
  )
}

function DeltaCell({ before, after, label }: { before: number; after: number; label: string }) {
  const pct = Math.round(before * 100)
  const aftPct = Math.round(after * 100)
  const delta = aftPct - pct
  const improved = delta < 0

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2">{label}</div>
      <div className="flex items-end gap-3">
        <div className="text-center">
          <div className="text-xs text-gray-600 mb-0.5">Before</div>
          <div className="text-xl font-bold text-red-400">{pct}%</div>
        </div>
        <div className="flex-1 flex justify-center pb-1">
          {improved
            ? <TrendingDown size={20} className="text-emerald-400" />
            : delta === 0
            ? <Minus size={20} className="text-gray-600" />
            : <TrendingUp size={20} className="text-red-400" />}
        </div>
        <div className="text-center">
          <div className="text-xs text-gray-600 mb-0.5">After</div>
          <div className={`text-xl font-bold ${improved ? 'text-emerald-400' : 'text-red-400'}`}>{aftPct}%</div>
        </div>
      </div>
      {delta !== 0 && (
        <div className={`text-xs text-center mt-2 font-semibold ${improved ? 'text-emerald-400' : 'text-red-400'}`}>
          {improved ? '▼' : '▲'} {Math.abs(delta)}pp {improved ? 'improvement' : 'increase'}
        </div>
      )}
    </div>
  )
}

// ── Step card ──────────────────────────────────────────────────────────────

function StepCard({
  step, selected, onToggle,
}: {
  step: MitigationStep
  selected: boolean
  onToggle: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const eff = Math.round(step.estimated_effectiveness * 100)

  return (
    <div className={`border rounded-xl transition-all ${
      selected ? 'border-brand-500/60 bg-brand-500/5' : 'border-gray-800 bg-gray-900/50'
    }`}>
      <div className="flex items-start gap-3 p-3">
        {/* Checkbox */}
        <button
          onClick={onToggle}
          className={`w-5 h-5 rounded border flex-shrink-0 mt-0.5 flex items-center justify-center transition-all ${
            selected ? 'bg-brand-500 border-brand-500' : 'border-gray-600 hover:border-gray-400'
          }`}
        >
          {selected && <CheckCircle size={12} className="text-white" />}
        </button>

        {/* Priority badge */}
        <div className="w-6 h-6 rounded-full bg-gray-800 flex items-center justify-center flex-shrink-0 text-xs font-bold text-gray-400">
          {step.priority}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-semibold text-white">{step.technique_name}</span>
            <LayerBadge layer={step.layer} />
            <span className={`text-[10px] ${COMPLEXITY_COLOR[step.complexity] || 'text-gray-400'}`}>
              {step.complexity} complexity
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{step.description}</p>

          {/* Effectiveness bar */}
          <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 h-1 bg-gray-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${eff >= 70 ? 'bg-emerald-500' : eff >= 40 ? 'bg-yellow-500' : 'bg-red-500'}`}
                style={{ width: `${eff}%` }}
              />
            </div>
            <span className="text-[10px] text-gray-500">{eff}% effective</span>
          </div>

          {/* Failures addressed */}
          {step.addresses_failures.length > 0 && (
            <div className="flex gap-1 mt-1.5 flex-wrap">
              {step.addresses_failures.map(f => (
                <span key={f} className="text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-500">
                  {f.replace(/_/g, ' ')}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Expand toggle */}
        <button
          onClick={() => setExpanded(v => !v)}
          className="text-gray-600 hover:text-gray-400 transition-colors flex-shrink-0 mt-0.5"
        >
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-gray-800 p-3 space-y-2">
          {step.prompt_instruction && (
            <div>
              <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-1">Prompt Instruction</div>
              <pre className="text-xs text-gray-400 bg-gray-950 p-2 rounded-lg whitespace-pre-wrap font-mono leading-relaxed">
                {step.prompt_instruction}
              </pre>
            </div>
          )}
          {step.implementation && (
            <div>
              <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-1">Implementation</div>
              <p className="text-xs text-gray-400">{step.implementation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── History Timeline ───────────────────────────────────────────────────────

function HistoryTimeline({ entries }: { entries: HistoryEntry[] }) {
  if (!entries.length) return (
    <div className="text-xs text-gray-600 text-center py-10">No mitigation history yet</div>
  )
  return (
    <div className="space-y-3">
      {entries.map((entry, i) => {
        const gradeColor = GRADE_COLORS[entry.grade] || GRADE_COLORS.F
        return (
          <div key={entry.plan_id + i} className="flex gap-3">
            {/* Timeline line */}
            <div className="flex flex-col items-center">
              <div className="w-2.5 h-2.5 rounded-full bg-brand-500 flex-shrink-0 mt-1" />
              {i < entries.length - 1 && <div className="w-px flex-1 bg-gray-800 mt-1" />}
            </div>

            {/* Card */}
            <div className="flex-1 pb-3">
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-gray-400">Run #{entry.run_id}</span>
                    <span className="text-[10px] text-gray-600">{new Date(entry.timestamp).toLocaleDateString()}</span>
                  </div>
                  <span className={`text-sm font-bold w-7 h-7 rounded-full border flex items-center justify-center ${gradeColor}`}>
                    {entry.grade}
                  </span>
                </div>

                <div className="flex gap-4 text-xs">
                  <div>
                    <span className="text-gray-600">ISR </span>
                    <span className="text-red-400">{Math.round(entry.original_isr * 100)}%</span>
                    <span className="text-gray-600 mx-1">→</span>
                    <span className="text-emerald-400">{Math.round(entry.hardened_isr * 100)}%</span>
                  </div>
                  <div>
                    <span className="text-gray-600">MES </span>
                    <span className="text-brand-400">{Math.round(entry.mes * 100)}%</span>
                  </div>
                  <div className="text-gray-600">{entry.techniques_count} techniques</div>
                </div>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function Mitigation() {
  const { runId } = useParams<{ runId?: string }>()

  const [plan, setPlan] = useState<MitigationPlan | null>(null)
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null)
  const [report, setReport] = useState<ComparisonReport | null>(null)
  const [history, setHistory] = useState<HistoryEntry[]>([])

  const [loadingPlan, setLoadingPlan] = useState(false)
  const [applying, setApplying] = useState(false)
  const [retesting, setRetesting] = useState(false)

  const [selectedTechniques, setSelectedTechniques] = useState<Set<string>>(new Set())
  const [hardenedPrompt, setHardenedPrompt] = useState('')
  const [activeTab, setActiveTab] = useState<'plan' | 'compare' | 'history'>('plan')

  useEffect(() => {
    if (!runId) return
    fetchPlan()
    loadHistory()
  }, [runId])

  // Persist history to localStorage whenever it changes
  useEffect(() => {
    if (history.length) {
      localStorage.setItem('mitigation_history', JSON.stringify(history.slice(0, 20)))
    }
  }, [history])

  const fetchPlan = async () => {
    if (!runId) return
    setLoadingPlan(true)
    try {
      const res = await client.post('/mitigation/plan', { run_id: parseInt(runId) })
      const p: MitigationPlan = res.data
      setPlan(p)
      setHardenedPrompt(p.hardened_prompt)
      setSelectedTechniques(new Set(p.steps.map(s => s.technique_id)))
    } catch (e: any) {
      toast.error('Failed to load mitigation plan: ' + e.message)
    } finally {
      setLoadingPlan(false)
    }
  }

  const handleApply = async () => {
    if (!plan) return
    setApplying(true)
    try {
      const res = await client.post('/mitigation/apply', {
        run_id: plan.run_id,
        selected_technique_ids: [...selectedTechniques],
      })
      setApplyResult(res.data)
      setHardenedPrompt(res.data.hardened_prompt)
      toast.success(`Applied ${res.data.active_techniques.length} mitigation techniques`)
    } catch (e: any) {
      toast.error('Apply failed: ' + e.message)
    } finally {
      setApplying(false)
    }
  }

  const handleRetest = async () => {
    if (!plan) return
    setRetesting(true)
    try {
      const res = await client.post('/mitigation/report', { run_id: plan.run_id })
      setReport(res.data)
      setActiveTab('compare')
      toast.success(`Grade: ${res.data.grade} · MES ${Math.round(res.data.mes * 100)}%`)
      const entry: HistoryEntry = {
        run_id: plan.run_id,
        plan_id: plan.plan_id,
        timestamp: new Date().toISOString(),
        original_isr: res.data.original_isr,
        hardened_isr: res.data.hardened_isr,
        mes: res.data.mes,
        grade: res.data.grade,
        techniques_count: plan.steps.length,
      }
      setHistory(prev => [entry, ...prev])
    } catch (e: any) {
      toast.error('Retest failed: ' + e.message)
    } finally {
      setRetesting(false)
    }
  }

  const loadHistory = () => {
    try {
      const stored = localStorage.getItem('mitigation_history')
      if (stored) setHistory(JSON.parse(stored))
    } catch { /* ignore */ }
  }

  const toggleTechnique = (id: string) => {
    setSelectedTechniques(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // ── No runId ─────────────────────────────────────────────────────────────
  if (!runId) {
    return (
      <div className="flex-1 flex flex-col">
        <TopBar title="Mitigation Lab" subtitle="AI-powered failure analysis and prompt hardening" />
        <div className="flex-1 p-6 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-brand-500/20 to-accent-red/20 flex items-center justify-center mb-4 border border-brand-500/20">
            <Shield size={28} className="text-brand-400" />
          </div>
          <h2 className="text-lg font-bold text-white mb-2">No Run Selected</h2>
          <p className="text-sm text-gray-500 max-w-sm mb-4">
            Navigate to a completed evaluation run from the Dashboard or Results page to start the mitigation analysis.
          </p>
          <Link to="/" className="inline-flex items-center gap-2 text-xs text-brand-400 hover:text-brand-300 transition-colors">
            <ArrowLeft size={14} /> Go to Dashboard
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col">
      <TopBar
        title={`Mitigation Lab — Run #${runId}`}
        subtitle="RCA · Mitigation Planning · Hardening · Before/After Comparison"
      />

      {/* Tabs */}
      <div className="flex items-center gap-1 px-5 pt-3 border-b border-gray-800 flex-shrink-0">
        {([
          { key: 'plan',    label: 'Mitigation Plan', Icon: Shield },
          { key: 'compare', label: 'Before / After',  Icon: Layers },
          { key: 'history', label: 'History',          Icon: History },
        ] as const).map(({ key, label, Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-t-lg border-b-2 transition-all ${
              activeTab === key
                ? 'text-white border-brand-500'
                : 'text-gray-500 border-transparent hover:text-gray-300'
            }`}
          >
            <Icon size={12} />
            {label}
            {key === 'compare' && report && (
              <span className={`text-[9px] font-bold ml-1 px-1.5 py-0.5 rounded-full border ${GRADE_COLORS[report.grade] || ''}`}>
                {report.grade}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── PLAN TAB ─────────────────────────────────────────────────────── */}
      {activeTab === 'plan' && (
        <div className="flex-1 flex overflow-hidden">

          {/* Left: RCA + steps */}
          <div className="flex-1 overflow-y-auto p-5 space-y-5">

            {loadingPlan && (
              <div className="flex flex-col items-center justify-center h-64">
                <div className="w-12 h-12 rounded-full border-4 border-brand-500/20 border-t-brand-500 animate-spin mb-3" />
                <p className="text-sm text-gray-400">Analyzing failures and building mitigation plan...</p>
              </div>
            )}

            {!loadingPlan && !plan && (
              <div className="flex flex-col items-center justify-center h-64 text-gray-700">
                <Shield size={40} className="mb-3 opacity-20" />
                <p className="text-sm">Loading plan...</p>
              </div>
            )}

            {plan && (
              <>
                {/* RCA Summary */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Target size={14} className="text-accent-red" />
                    <h2 className="text-xs font-bold text-gray-300 uppercase tracking-wide">Root Cause Analysis</h2>
                    <span className="text-[10px] text-gray-600 ml-auto font-mono">{plan.plan_id}</span>
                  </div>

                  <div className="grid grid-cols-3 gap-3 mb-3">
                    {[
                      { label: 'Original ISR',    val: `${Math.round(plan.original_isr * 100)}%`,  color: 'text-red-400' },
                      { label: 'Attack Failures',  val: String(plan.total_failures),                color: 'text-yellow-400' },
                      { label: 'Techniques Found', val: String(plan.steps.length),                  color: 'text-brand-400' },
                    ].map(({ label, val, color }) => (
                      <div key={label} className="bg-gray-950 rounded-lg p-3 text-center">
                        <div className={`text-xl font-bold ${color}`}>{val}</div>
                        <div className="text-[10px] text-gray-600 mt-0.5">{label}</div>
                      </div>
                    ))}
                  </div>

                  {/* Failure modes */}
                  {plan.failure_modes_detected.length > 0 && (
                    <div>
                      <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-1.5">Failure Modes Detected</div>
                      <div className="flex flex-wrap gap-1.5">
                        {plan.failure_modes_detected.map(fm => (
                          <span key={fm} className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg bg-red-950/40 border border-red-800/40 text-red-300">
                            <AlertTriangle size={9} />
                            {fm.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {plan.priority_recommendation && (
                    <div className="mt-3 p-2.5 rounded-lg bg-brand-500/10 border border-brand-500/20 text-xs text-brand-300">
                      <span className="font-semibold">Recommendation: </span>{plan.priority_recommendation}
                    </div>
                  )}
                </div>

                {/* Mitigation Steps */}
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Lock size={13} className="text-accent-red" />
                      <h2 className="text-xs font-bold text-gray-300 uppercase tracking-wide">
                        Mitigation Steps ({plan.steps.length})
                      </h2>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-600">{selectedTechniques.size} selected</span>
                      <button
                        onClick={() => setSelectedTechniques(new Set(plan.steps.map(s => s.technique_id)))}
                        className="text-[10px] text-brand-400 hover:text-brand-300 transition-colors"
                      >
                        All
                      </button>
                      <span className="text-gray-700">·</span>
                      <button
                        onClick={() => setSelectedTechniques(new Set())}
                        className="text-[10px] text-gray-500 hover:text-gray-400 transition-colors"
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {plan.steps.map(step => (
                      <StepCard
                        key={step.technique_id}
                        step={step}
                        selected={selectedTechniques.has(step.technique_id)}
                        onToggle={() => toggleTechnique(step.technique_id)}
                      />
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>

          {/* Right: Hardened prompt + actions */}
          <div className="w-80 border-l border-gray-800 flex flex-col overflow-hidden">
            <div className="flex-1 overflow-y-auto p-4 space-y-4">

              {/* Projected improvement */}
              {plan && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-3">Projected Impact</div>
                  <div className="space-y-2">
                    {[
                      { label: 'Current ISR',   val: `${Math.round(plan.original_isr * 100)}%`,                 color: 'text-red-400' },
                      { label: 'Residual ISR',  val: `${Math.round(plan.estimated_residual_isr * 100)}%`,        color: 'text-yellow-400' },
                      { label: 'Est. MES',      val: `${Math.round(plan.estimated_mes * 100)}%`,                 color: 'text-emerald-400' },
                      { label: 'Confidence',    val: `${Math.round(plan.confidence * 100)}%`,                    color: 'text-gray-400' },
                    ].map(({ label, val, color }) => (
                      <div key={label} className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{label}</span>
                        <span className={`text-xs font-bold ${color}`}>{val}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Hardened prompt editor */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <FileText size={12} className="text-accent-red" />
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wide">Hardened System Prompt</span>
                </div>
                <textarea
                  rows={10}
                  value={hardenedPrompt}
                  onChange={e => setHardenedPrompt(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl px-3 py-2.5 text-xs text-gray-300
                             font-mono resize-none focus:outline-none focus:border-brand-500/50 leading-relaxed"
                  placeholder="Hardened prompt will appear after generating the plan..."
                />
                <p className="text-[10px] text-gray-600 mt-1">You can edit before applying</p>
              </div>

              {/* Guardrails */}
              {((applyResult?.guardrails ?? plan?.guardrails) || []).length > 0 && (
                <div>
                  <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-2 flex items-center gap-1">
                    <Shield size={10} /> Active Guardrails
                  </div>
                  <div className="space-y-1.5">
                    {(applyResult?.guardrails ?? plan?.guardrails ?? []).map((g: any, i: number) => (
                      <div key={i} className="p-2 rounded-lg bg-gray-900 border border-gray-800 text-xs">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-brand-500/20 text-brand-400 font-bold uppercase">
                            {g.type || g.layer || 'rule'}
                          </span>
                          <span className="text-gray-400 font-medium">{g.target || g.name}</span>
                        </div>
                        {(g.description || g.rule) && (
                          <p className="text-gray-600 text-[10px] leading-relaxed">{g.description || g.rule}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Action buttons */}
            <div className="p-4 border-t border-gray-800 space-y-2">
              <button
                onClick={handleApply}
                disabled={applying || !plan || selectedTechniques.size === 0}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold
                           bg-gradient-to-r from-brand-500 to-brand-600 text-white
                           hover:from-brand-600 hover:to-brand-700 transition-all
                           disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-brand-900/30"
              >
                {applying ? <Loader size={14} className="animate-spin" /> : <Play size={14} />}
                Apply Mitigation
              </button>

              <button
                onClick={handleRetest}
                disabled={retesting || !plan}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold
                           border border-emerald-700/60 text-emerald-400
                           hover:bg-emerald-950/30 transition-all
                           disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {retesting ? <Loader size={14} className="animate-spin" /> : <RotateCcw size={14} />}
                Re-test & Compare
              </button>

              <button
                onClick={fetchPlan}
                disabled={loadingPlan}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-xl text-xs text-gray-500
                           hover:text-gray-300 hover:bg-gray-800/50 transition-all"
              >
                <RefreshCw size={12} className={loadingPlan ? 'animate-spin' : ''} />
                Re-analyze
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── COMPARE TAB ──────────────────────────────────────────────────── */}
      {activeTab === 'compare' && (
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {!report ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-700">
              <Layers size={40} className="mb-3 opacity-20" />
              <p className="text-sm font-medium">No comparison data yet</p>
              <p className="text-xs mt-1 opacity-60">Run "Re-test & Compare" from the Mitigation Plan tab</p>
              <button
                onClick={() => setActiveTab('plan')}
                className="mt-4 flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 transition-colors"
              >
                <ChevronRight size={13} /> Go to Plan
              </button>
            </div>
          ) : (
            <>
              {/* Grade banner */}
              <div className={`flex items-center gap-4 p-4 rounded-xl border ${GRADE_COLORS[report.grade] || GRADE_COLORS.F}`}>
                <Award size={28} />
                <div className="flex-1">
                  <div className="text-sm font-bold">Mitigation Grade: {report.grade}</div>
                  <div className="text-xs mt-0.5 opacity-75">{report.summary}</div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold">{Math.round(report.mes * 100)}%</div>
                  <div className="text-[10px] opacity-60">MES Score</div>
                </div>
              </div>

              {/* Delta metrics */}
              <div className="grid grid-cols-3 gap-4">
                <DeltaCell before={report.original_isr}  after={report.hardened_isr}  label="Injection Success Rate" />
                <DeltaCell before={report.original_dls}  after={report.hardened_dls}  label="Data Leakage Score" />
                <DeltaCell before={report.original_idi}  after={report.hardened_idi}  label="Instruction Drift Index" />
              </div>

              {/* ISR Improvement */}
              {report.isr_improvement_pct > 0 && (
                <div className="bg-emerald-950/20 border border-emerald-800/30 rounded-xl p-4 flex items-center gap-3">
                  <TrendingDown size={20} className="text-emerald-400 flex-shrink-0" />
                  <div>
                    <div className="text-sm font-bold text-emerald-400">
                      {Math.round(report.isr_improvement_pct)}% ISR Reduction
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      {report.mitigation_steps_count} techniques applied · {report.failure_modes_detected.length} failure modes addressed
                    </div>
                  </div>
                </div>
              )}

              {/* Failure modes addressed */}
              {report.failure_modes_detected.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-bold text-gray-400 uppercase tracking-wide mb-2 flex items-center gap-2">
                    <AlertTriangle size={12} className="text-accent-red" /> Failure Modes Addressed
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {report.failure_modes_detected.map(fm => (
                      <span key={fm} className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg bg-gray-800 text-gray-400 border border-gray-700">
                        <CheckCircle size={10} className="text-emerald-400" />
                        {fm.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendation */}
              {report.priority_recommendation && (
                <div className="p-4 rounded-xl bg-brand-500/10 border border-brand-500/20">
                  <div className="text-xs font-bold text-brand-400 mb-1">Next Steps</div>
                  <p className="text-xs text-gray-400">{report.priority_recommendation}</p>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ── HISTORY TAB ──────────────────────────────────────────────────── */}
      {activeTab === 'history' && (
        <div className="flex-1 overflow-y-auto p-5">
          <div className="flex items-center gap-2 mb-4">
            <History size={14} className="text-accent-red" />
            <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wide">Mitigation History</h2>
            <span className="text-[10px] text-gray-600 ml-auto">{history.length} entries</span>
          </div>
          <div className="max-w-2xl">
            <HistoryTimeline entries={history} />
          </div>
        </div>
      )}
    </div>
  )
}
