import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import client from '../api/client'
import toast from 'react-hot-toast'
import {
  Shield, ArrowRight, Loader, CheckCircle, AlertTriangle,
  TrendingDown, TrendingUp, Lock, FileText, Zap,
  ChevronDown, ChevronUp, XCircle, Minus, ArrowLeft,
  Target, Layers, BarChart2, Activity,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

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

interface RetestResult {
  run_id: number
  original_isr: number
  hardened_isr: number
  improvement_pct: number
  total_attacks: number
  blocked_by_input_guard: number
  blocked_by_prompt_hardening: number
  blocked_by_output_guard: number
  per_attack: PerAttackResult[]
}

interface PerAttackResult {
  attack_name: string
  category: string
  severity: string
  before_classification: string
  before_success: boolean
  after_classification: string
  after_success: boolean
  blocked_by: string
  payload_preview: string
  before_response_preview: string
  after_response_preview: string
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

const BLOCKER_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  input_guard:       { bg: 'bg-purple-950/40 border-purple-700', text: 'text-purple-300', label: 'Input Guard' },
  hardened_prompt:   { bg: 'bg-blue-950/40 border-blue-700',     text: 'text-blue-300',   label: 'Hardened Prompt' },
  output_guard:      { bg: 'bg-amber-950/40 border-amber-700',   text: 'text-amber-300',  label: 'Output Guard' },
  none:              { bg: 'bg-red-950/40 border-red-700',        text: 'text-red-300',    label: 'Bypassed' },
  not_applicable:    { bg: 'bg-green-950/40 border-green-800',   text: 'text-green-400',  label: 'Already Safe' },
}

function getISRColor(isr: number) {
  if (isr >= 0.6) return '#ef4444'
  if (isr >= 0.4) return '#f97316'
  if (isr >= 0.2) return '#eab308'
  return '#22c55e'
}

function getGrade(isr: number) {
  if (isr < 0.05) return 'A'
  if (isr < 0.15) return 'B'
  if (isr < 0.30) return 'C'
  if (isr < 0.50) return 'D'
  return 'F'
}

const GRADE_COLORS: Record<string, string> = {
  A: 'text-emerald-400 border-emerald-700 bg-emerald-950/40',
  B: 'text-green-400 border-green-700 bg-green-950/40',
  C: 'text-yellow-400 border-yellow-700 bg-yellow-950/40',
  D: 'text-orange-400 border-orange-700 bg-orange-950/40',
  F: 'text-red-400 border-red-700 bg-red-950/40',
}

// ── Phase indicator ────────────────────────────────────────────────────────

function PhaseStep({ n, label, done, active }: { n: number; label: string; done: boolean; active: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
        done ? 'bg-green-600 text-white' :
        active ? 'text-white shadow-[0_0_10px_rgba(232,0,61,0.4)]' :
        'bg-white/06 text-gray-600'
      }`} style={active ? { background: 'linear-gradient(135deg, #e8003d, #6366f1)' } : {}}>
        {done ? <CheckCircle size={14} /> : n}
      </div>
      <span className={`text-xs font-medium ${done ? 'text-green-400' : active ? 'text-white' : 'text-gray-600'}`}>
        {label}
      </span>
    </div>
  )
}

// ── Prompt Diff View ────────────────────────────────────────────────────────

function PromptDiff({ original, hardened }: { original: string; hardened: string }) {
  const [showDiff, setShowDiff] = useState(true)

  const origLines = original.split('\n')
  const hardLines = hardened.split('\n')

  const addedLines = hardLines.filter(l => !origLines.some(o => o.trim() === l.trim() && l.trim() !== ''))
  const removedLines: string[] = []
  const keptLines = hardLines.filter(l => origLines.some(o => o.trim() === l.trim()))

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wide">System Prompt — Before vs After</span>
        <button
          onClick={() => setShowDiff(s => !s)}
          className="text-[10px] text-indigo-400 flex items-center gap-1 hover:text-indigo-300 transition-colors"
        >
          {showDiff ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          {showDiff ? 'Hide' : 'Show'} diff
        </button>
      </div>

      {showDiff && (
        <div className="rounded-xl border border-white/08 overflow-hidden">
          {/* Before */}
          <div className="border-b border-white/06">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-red-950/20 border-b border-red-800/20">
              <Minus size={11} className="text-red-400" />
              <span className="text-[10px] text-red-400 font-mono">BEFORE — Original prompt</span>
            </div>
            <pre className="text-[10px] text-gray-400 font-mono p-3 bg-red-950/10 whitespace-pre-wrap leading-relaxed max-h-36 overflow-y-auto">
              {original || '(empty)'}
            </pre>
          </div>
          {/* After */}
          <div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-green-950/20 border-b border-green-800/20">
              <CheckCircle size={11} className="text-green-400" />
              <span className="text-[10px] text-green-400 font-mono">AFTER — Hardened prompt</span>
            </div>
            <pre className="text-[10px] font-mono p-3 bg-green-950/10 whitespace-pre-wrap leading-relaxed max-h-36 overflow-y-auto">
              {hardened.split('\n').map((line, i) => {
                const isNew = !origLines.some(o => o.trim() === line.trim() && line.trim() !== '')
                return (
                  <span key={i} className={isNew ? 'text-green-300' : 'text-gray-400'}>
                    {line}{'\n'}
                  </span>
                )
              })}
            </pre>
          </div>
          {/* Stats */}
          {addedLines.length > 0 && (
            <div className="flex items-center gap-3 px-3 py-2 bg-white/02 border-t border-white/06">
              <span className="text-[10px] text-green-400">+{addedLines.length} lines added</span>
              <span className="text-[10px] text-red-400">-{removedLines.length} lines removed</span>
              <span className="text-[10px] text-gray-600">{keptLines.length} lines unchanged</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── ISR Comparison Ring ────────────────────────────────────────────────────

function ISRRing({ value, label, size = 80 }: { value: number; label: string; size?: number }) {
  const color = getISRColor(value)
  const pct = Math.round(value * 100)
  const r = 14, circ = 2 * Math.PI * r
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
          <circle cx="18" cy="18" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
          <circle cx="18" cy="18" r={r} fill="none" stroke={color} strokeWidth="3"
            strokeDasharray={`${(pct / 100) * circ} ${circ}`} strokeLinecap="round"
            style={{ transition: 'stroke-dasharray 0.8s ease' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-base font-bold text-white leading-none">{pct}%</span>
          <span className="text-[8px] text-gray-500 leading-none mt-0.5">ISR</span>
        </div>
      </div>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  )
}

// ── Attack Comparison Row ──────────────────────────────────────────────────

function AttackCompRow({ attack }: { attack: PerAttackResult }) {
  const [expanded, setExpanded] = useState(false)
  const blocker = BLOCKER_COLORS[attack.blocked_by] || BLOCKER_COLORS.none

  return (
    <div className="border border-white/06 rounded-xl overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-2.5 cursor-pointer select-none hover:bg-white/02 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Before */}
        <div className="w-20 flex-shrink-0">
          <span className={`text-[10px] font-bold uppercase ${
            attack.before_success ? 'text-red-400' : 'text-green-400'
          }`}>
            {attack.before_success ? 'BYPASSED' : 'BLOCKED'}
          </span>
        </div>

        {/* Arrow */}
        <ArrowRight size={12} className="text-gray-600 flex-shrink-0" />

        {/* After */}
        <div className="w-24 flex-shrink-0">
          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${blocker.bg} ${blocker.text}`}>
            {blocker.label}
          </span>
        </div>

        {/* Attack name */}
        <div className="flex-1 min-w-0">
          <span className="text-xs text-gray-300 truncate">{attack.attack_name.replace(/_/g, ' ')}</span>
          <span className="text-[10px] text-gray-600 ml-2 capitalize">{attack.category.replace(/_/g, ' ')}</span>
        </div>

        {/* Severity */}
        <span className={`text-[10px] flex-shrink-0 ${
          attack.severity === 'critical' ? 'text-red-400' :
          attack.severity === 'high' ? 'text-orange-400' :
          attack.severity === 'medium' ? 'text-yellow-400' : 'text-gray-500'
        }`}>{attack.severity}</span>

        {expanded ? <ChevronUp size={12} className="text-gray-600" /> : <ChevronDown size={12} className="text-gray-600" />}
      </div>

      {expanded && (
        <div className="px-4 pb-3 grid grid-cols-2 gap-3 border-t border-white/06 pt-3">
          <div>
            <div className="text-[9px] text-red-400 uppercase tracking-wide mb-1 flex items-center gap-1">
              <XCircle size={9} /> Before (Attack Succeeded)
            </div>
            <div className="text-[10px] text-gray-500 bg-red-950/10 border border-red-900/30 rounded-lg p-2 leading-relaxed">
              <div className="text-[9px] text-gray-600 mb-1">Payload preview:</div>
              <div className="text-gray-400 mb-2">{attack.payload_preview || '(no payload recorded)'}</div>
              <div className="text-[9px] text-gray-600 mb-1">Model response:</div>
              <div className="text-red-300/80">{attack.before_response_preview || '(complied with attack)'}</div>
            </div>
          </div>
          <div>
            <div className="text-[9px] text-green-400 uppercase tracking-wide mb-1 flex items-center gap-1">
              <CheckCircle size={9} /> After (Blocked by {blocker.label})
            </div>
            <div className="text-[10px] text-gray-500 bg-green-950/10 border border-green-900/30 rounded-lg p-2 leading-relaxed">
              <div className="text-[9px] text-gray-600 mb-1">Defense applied:</div>
              <div className={`mb-2 font-medium ${blocker.text}`}>{blocker.label}</div>
              <div className="text-[9px] text-gray-600 mb-1">Response after mitigation:</div>
              <div className="text-green-300/80">{attack.after_response_preview || 'Request was blocked.'}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Empty State (no runId) ─────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-10 text-center gap-6">
      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: 'linear-gradient(135deg, rgba(232,0,61,0.12), rgba(99,102,241,0.12))', border: '1px solid rgba(232,0,61,0.2)' }}>
        <Shield size={28} style={{ color: '#e8003d' }} />
      </div>
      <div>
        <h2 className="text-lg font-bold text-white mb-2">No Evaluation Loaded</h2>
        <p className="text-sm text-gray-500 max-w-md">
          Run an evaluation first, then click "Go to Mitigation" after the pipeline completes.
          The mitigation system will analyze your results and apply multi-layer defenses.
        </p>
      </div>
      <div className="flex gap-3">
        <Link to="/run"
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white transition-all"
          style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 16px rgba(232,0,61,0.25)' }}>
          <Zap size={14} /> Run Evaluation
        </Link>
        <Link to="/results"
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium text-gray-400 border border-white/08 hover:text-gray-200 transition-all">
          <BarChart2 size={14} /> View Results
        </Link>
      </div>
      <div className="grid grid-cols-3 gap-4 max-w-2xl w-full mt-2">
        {[
          { icon: Target, label: 'Step 1', desc: 'Run attack evaluation on your LLM', color: '#22c55e' },
          { icon: Shield, label: 'Step 2', desc: 'Click "Go to Mitigation" to analyze results', color: '#6366f1' },
          { icon: CheckCircle, label: 'Step 3', desc: 'Apply mitigation & see ISR improvement', color: '#e8003d' },
        ].map(({ icon: Icon, label, desc, color }) => (
          <div key={label} className="p-4 rounded-xl border text-center"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
            <Icon size={20} className="mx-auto mb-2" style={{ color }} />
            <div className="text-xs font-bold text-white mb-1">{label}</div>
            <div className="text-[10px] text-gray-500">{desc}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

type Phase = 'analysis' | 'plan' | 'apply' | 'retest' | 'results'

export default function Mitigation() {
  const { runId } = useParams<{ runId?: string }>()
  const navigate = useNavigate()

  const [phase, setPhase] = useState<Phase>('analysis')
  const [plan, setPlan] = useState<MitigationPlan | null>(null)
  const [retestResult, setRetestResult] = useState<RetestResult | null>(null)
  const [originalPrompt, setOriginalPrompt] = useState('')

  const [loadingAnalysis, setLoadingAnalysis] = useState(false)
  const [applying, setApplying] = useState(false)
  const [retesting, setRetesting] = useState(false)
  const [expandedCategories, setExpandedCategories] = useState(false)

  useEffect(() => {
    if (runId) {
      loadAnalysis()
    }
  }, [runId])

  const loadAnalysis = async () => {
    if (!runId) return
    setLoadingAnalysis(true)
    try {
      // Fetch original system prompt from evaluation
      const evalRes = await client.get(`/evaluations/${runId}`)
      setOriginalPrompt(evalRes.data?.system_prompt || '')

      // Build mitigation plan (includes RCA + hardened prompt)
      const res = await client.post('/mitigation/plan', { run_id: parseInt(runId) })
      setPlan(res.data)
      setPhase('analysis')
    } catch (e: any) {
      toast.error('Failed to load analysis: ' + (e.response?.data?.detail || e.message))
    } finally {
      setLoadingAnalysis(false)
    }
  }

  const handleApplyMitigation = async () => {
    if (!plan || !runId) return
    setApplying(true)
    setPhase('apply')
    try {
      await client.post('/mitigation/apply', {
        run_id: plan.run_id,
        selected_technique_ids: plan.steps.map(s => s.technique_id),
      })
      toast.success('Mitigation applied — running retest...')
      await runRetest()
    } catch (e: any) {
      toast.error('Apply failed: ' + (e.response?.data?.detail || e.message))
      setPhase('plan')
    } finally {
      setApplying(false)
    }
  }

  const runRetest = async () => {
    if (!plan) return
    setRetesting(true)
    setPhase('retest')
    try {
      const res = await client.post('/mitigation/retest', {
        run_id: plan.run_id,
        hardened_prompt: plan.hardened_prompt,
      })
      setRetestResult(res.data)
      setPhase('results')
      const improvement = res.data.improvement_pct
      toast.success(`Retest complete — ISR reduced by ${improvement.toFixed(1)}%`)
    } catch (e: any) {
      toast.error('Retest failed: ' + (e.response?.data?.detail || e.message))
      setPhase('plan')
    } finally {
      setRetesting(false)
    }
  }

  if (!runId) {
    return (
      <div className="flex-1 flex flex-col">
        <TopBar title="Mitigation Lab" subtitle="Analysis-first, data-driven vulnerability remediation" />
        <EmptyState />
      </div>
    )
  }

  const phaseOrder: Phase[] = ['analysis', 'plan', 'apply', 'retest', 'results']
  const phaseIdx = phaseOrder.indexOf(phase)
  const isDone = (p: Phase) => phaseOrder.indexOf(p) < phaseIdx

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar
        title={`Mitigation Lab — Run #${runId}`}
        subtitle="Analysis → Plan → Apply → Retest → Before/After"
      />

      {/* Phase indicator */}
      <div className="flex items-center gap-4 px-6 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.15)' }}>
        <button onClick={() => navigate(-1)}
          className="flex items-center gap-1.5 text-[10px] text-gray-500 hover:text-gray-300 transition-colors mr-2">
          <ArrowLeft size={11} /> Back
        </button>
        <div className="flex items-center gap-3">
          <PhaseStep n={1} label="Analysis" done={isDone('analysis')} active={phase === 'analysis'} />
          <div className="w-6 h-px bg-white/10" />
          <PhaseStep n={2} label="Mitigation Plan" done={isDone('plan')} active={phase === 'plan'} />
          <div className="w-6 h-px bg-white/10" />
          <PhaseStep n={3} label="Apply" done={isDone('apply') || phase === 'retest' || phase === 'results'} active={phase === 'apply'} />
          <div className="w-6 h-px bg-white/10" />
          <PhaseStep n={4} label="Retest" done={isDone('retest') || phase === 'results'} active={phase === 'retest'} />
          <div className="w-6 h-px bg-white/10" />
          <PhaseStep n={5} label="Results" done={false} active={phase === 'results'} />
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">

        {/* Loading Analysis */}
        {loadingAnalysis && (
          <div className="flex flex-col items-center justify-center h-64 gap-4">
            <div className="w-12 h-12 rounded-full border-4 border-white/06 border-t-pink-500 animate-spin" />
            <div className="text-sm text-gray-400">Analyzing failures and building root cause analysis...</div>
          </div>
        )}

        {/* ── PHASE 1+2: Analysis & Plan ────────────────────────────────────── */}
        {!loadingAnalysis && plan && (phase === 'analysis' || phase === 'plan') && (
          <div className="p-6 max-w-5xl mx-auto space-y-6">

            {/* ─ Section 1: Root Cause Analysis ─ */}
            <div className="rounded-2xl border overflow-hidden"
              style={{ borderColor: 'rgba(232,0,61,0.2)', background: 'rgba(232,0,61,0.04)' }}>
              <div className="flex items-center gap-3 px-5 py-3"
                style={{ borderBottom: '1px solid rgba(232,0,61,0.12)', background: 'rgba(232,0,61,0.08)' }}>
                <Target size={14} style={{ color: '#e8003d' }} />
                <span className="text-sm font-bold text-white">Root Cause Analysis</span>
                <span className="text-[10px] text-red-400 bg-red-950/40 px-2 py-0.5 rounded-full ml-auto">
                  Why did attacks succeed?
                </span>
              </div>
              <div className="p-5">
                <div className="grid grid-cols-3 gap-4 mb-5">
                  {[
                    { label: 'Original ISR',       val: `${Math.round(plan.original_isr * 100)}%`,  color: '#ef4444', sub: 'Attack success rate' },
                    { label: 'Attacks Failed',      val: String(plan.total_failures),                color: '#f97316', sub: 'Successful attacks' },
                    { label: 'Defense Techniques',  val: String(plan.steps.length),                  color: '#6366f1', sub: 'Mitigations found' },
                  ].map(({ label, val, color, sub }) => (
                    <div key={label} className="text-center py-4 rounded-xl border border-white/06 bg-white/02">
                      <div className="text-2xl font-bold" style={{ color }}>{val}</div>
                      <div className="text-xs font-medium text-white mt-0.5">{label}</div>
                      <div className="text-[10px] text-gray-600 mt-0.5">{sub}</div>
                    </div>
                  ))}
                </div>

                {/* Failure modes */}
                {plan.failure_modes_detected.length > 0 && (
                  <div className="mb-4">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                      <AlertTriangle size={10} className="text-red-400" /> Vulnerable Attack Categories
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {plan.failure_modes_detected.map(fm => (
                        <span key={fm} className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg bg-red-950/30 border border-red-800/40 text-red-300">
                          <XCircle size={10} />
                          {fm.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Attack success patterns */}
                <div className="mb-4">
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                    <Activity size={10} className="text-orange-400" /> Attack Success Patterns Detected
                  </div>
                  <div className="space-y-2">
                    {plan.steps.slice(0, 4).map(s => (
                      <div key={s.technique_id} className="flex items-start gap-3 text-xs bg-white/02 rounded-xl p-3 border border-white/06">
                        <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 bg-orange-400" />
                        <div>
                          <span className="text-orange-300 font-medium">{s.technique_name.replace(/_/g, ' ')}: </span>
                          <span className="text-gray-400">{s.description}</span>
                        </div>
                        <div className="ml-auto flex-shrink-0">
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${LAYER_COLORS[s.layer] || LAYER_COLORS.architecture}`}>
                            {s.layer}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {plan.priority_recommendation && (
                  <div className="p-3 rounded-xl bg-indigo-950/30 border border-indigo-800/30 text-xs text-indigo-300">
                    <span className="font-bold">Key Finding: </span>{plan.priority_recommendation}
                  </div>
                )}
              </div>
            </div>

            {/* ─ Section 2: Mitigation Plan ─ */}
            <div className="rounded-2xl border overflow-hidden"
              style={{ borderColor: 'rgba(99,102,241,0.2)', background: 'rgba(99,102,241,0.04)' }}>
              <div className="flex items-center gap-3 px-5 py-3"
                style={{ borderBottom: '1px solid rgba(99,102,241,0.12)', background: 'rgba(99,102,241,0.08)' }}>
                <Shield size={14} className="text-indigo-400" />
                <span className="text-sm font-bold text-white">Detailed Mitigation Plan</span>
                <span className="text-[10px] text-indigo-400 ml-auto">{plan.steps.length} defense techniques</span>
              </div>
              <div className="p-5 space-y-4">

                {/* Strategy overview */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="rounded-xl border border-white/06 bg-white/02 p-4">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2">Strategy Type</div>
                    <div className="flex flex-wrap gap-1.5">
                      {['prompt_hardening', 'input_filtering', 'output_filtering'].map(s => {
                        const has = plan.steps.some(st => st.layer === s.split('_')[0])
                        return (
                          <span key={s} className={`text-[10px] px-2 py-1 rounded-lg border font-medium ${
                            has ? 'bg-indigo-950/40 border-indigo-700 text-indigo-300' : 'bg-white/02 border-white/06 text-gray-600'
                          }`}>
                            {s.replace(/_/g, ' ')}
                          </span>
                        )
                      })}
                      <span className="text-[10px] px-2 py-1 rounded-lg border bg-indigo-950/40 border-indigo-700 text-indigo-300 font-medium">
                        combined
                      </span>
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/06 bg-white/02 p-4">
                    <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2">Projected Impact</div>
                    <div className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-gray-500">Current ISR</span>
                        <span className="text-red-400 font-bold">{Math.round(plan.original_isr * 100)}%</span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-gray-500">After Mitigation (est.)</span>
                        <span className="text-green-400 font-bold">{Math.round(plan.estimated_residual_isr * 100)}%</span>
                      </div>
                      <div className="flex justify-between text-xs">
                        <span className="text-gray-500">Est. Effectiveness</span>
                        <span className="text-indigo-400 font-bold">{Math.round(plan.estimated_mes * 100)}%</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Specific rules / techniques */}
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                    <Lock size={10} /> Specific Defense Rules Being Applied
                  </div>
                  <div className="space-y-2">
                    {plan.steps.map(step => (
                      <div key={step.technique_id} className="flex items-start gap-3 rounded-xl border border-white/06 bg-white/02 p-3">
                        <div className="w-5 h-5 rounded-full bg-green-900/40 border border-green-700/50 flex items-center justify-center flex-shrink-0 mt-0.5">
                          <CheckCircle size={11} className="text-green-400" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-semibold text-white">{step.technique_name}</span>
                            <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${LAYER_COLORS[step.layer] || LAYER_COLORS.architecture}`}>
                              {step.layer}
                            </span>
                            <span className="text-[10px] text-gray-500">
                              {Math.round(step.estimated_effectiveness * 100)}% effective
                            </span>
                          </div>
                          <p className="text-[11px] text-gray-500 mt-0.5">{step.description}</p>
                          {step.addresses_failures.length > 0 && (
                            <div className="flex gap-1 mt-1 flex-wrap">
                              {step.addresses_failures.map(f => (
                                <span key={f} className="text-[9px] px-1.5 py-0.5 rounded bg-red-950/30 text-red-400">
                                  {f.replace(/_/g, ' ')}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        {/* Effectiveness bar */}
                        <div className="w-20 flex-shrink-0">
                          <div className="h-1.5 bg-white/06 rounded-full overflow-hidden">
                            <div className="h-full rounded-full bg-green-500 transition-all"
                              style={{ width: `${Math.round(step.estimated_effectiveness * 100)}%` }} />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Guardrails */}
                {plan.guardrails.length > 0 && (
                  <div>
                    <div className="text-[10px] text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1.5">
                      <Layers size={10} /> Active Guardrails & Rules
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {plan.guardrails.slice(0, 6).map((g: any, i: number) => (
                        <div key={i} className="text-xs bg-white/02 border border-white/06 rounded-xl p-3">
                          <div className="flex items-center gap-1.5 mb-1">
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-indigo-950/40 text-indigo-400 font-bold uppercase">
                              {g.type || g.layer || 'rule'}
                            </span>
                            <span className="text-gray-300 font-medium">{g.target || g.name}</span>
                          </div>
                          {(g.description || g.rule) && (
                            <p className="text-[10px] text-gray-600">{g.description || g.rule}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* ─ Section 3: Transparency — What Exactly Changes ─ */}
            <div className="rounded-2xl border border-white/08 bg-white/02 overflow-hidden">
              <div className="flex items-center gap-3 px-5 py-3 border-b border-white/06 bg-white/02">
                <FileText size={14} className="text-yellow-400" />
                <span className="text-sm font-bold text-white">What Exactly Changes</span>
                <span className="text-[10px] text-yellow-400 ml-auto">Full transparency</span>
              </div>
              <div className="p-5 space-y-4">
                <PromptDiff original={originalPrompt} hardened={plan.hardened_prompt} />

                {/* Strategy explanation */}
                <div className="p-3 rounded-xl bg-yellow-950/20 border border-yellow-800/30 text-xs text-yellow-300/80">
                  <span className="font-bold text-yellow-300">Why this mitigation was selected: </span>
                  {plan.priority_recommendation ||
                    `Based on ${plan.failure_modes_detected.length} failure modes, a combined prompt hardening + input/output filtering strategy was selected. This addresses ${plan.steps.length} vulnerability patterns using ${plan.steps.filter(s => s.estimated_effectiveness > 0.6).length} high-effectiveness techniques.`}
                </div>
              </div>
            </div>

            {/* ─ Single Apply Button ─ */}
            <div className="sticky bottom-0 py-4" style={{ background: 'linear-gradient(to top, rgba(10,13,24,1) 60%, transparent)' }}>
              <button
                onClick={handleApplyMitigation}
                disabled={applying || retesting}
                className="w-full py-4 rounded-2xl text-base font-bold text-white flex items-center justify-center gap-3 transition-all disabled:opacity-50"
                style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 30px rgba(232,0,61,0.3)' }}>
                {applying ? (
                  <><Loader size={16} className="animate-spin" /> Applying Mitigation...</>
                ) : (
                  <><Shield size={16} /> Apply Mitigation <ArrowRight size={16} /></>
                )}
              </button>
              <p className="text-[10px] text-gray-600 text-center mt-2">
                Applies {plan.steps.length} defense techniques · Input Guard + Hardened Prompt + Output Guard
              </p>
            </div>
          </div>
        )}

        {/* ── PHASE 3: Applying ─────────────────────────────────────────────── */}
        {phase === 'apply' && (
          <div className="flex flex-col items-center justify-center h-64 gap-4">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ background: 'linear-gradient(135deg, rgba(232,0,61,0.15), rgba(99,102,241,0.15))' }}>
              <Shield size={24} className="text-indigo-400 animate-pulse" />
            </div>
            <div className="text-sm font-bold text-white">Applying Multi-Layer Defense...</div>
            <div className="flex flex-col gap-2 text-xs text-gray-500 text-center">
              <div className="flex items-center gap-2"><CheckCircle size={12} className="text-purple-400" /> Input Guard deployed</div>
              <div className="flex items-center gap-2"><Loader size={12} className="animate-spin text-indigo-400" /> Hardening system prompt</div>
              <div className="flex items-center gap-2 opacity-40"><CheckCircle size={12} /> Output Guard queued</div>
            </div>
          </div>
        )}

        {/* ── PHASE 4: Retesting ────────────────────────────────────────────── */}
        {phase === 'retest' && (
          <div className="flex flex-col items-center justify-center h-64 gap-4">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
              style={{ background: 'linear-gradient(135deg, rgba(34,197,94,0.15), rgba(99,102,241,0.15))' }}>
              <Activity size={24} className="text-green-400 animate-pulse" />
            </div>
            <div className="text-sm font-bold text-white">Re-Testing with Hardened System...</div>
            <div className="text-xs text-gray-500">Running {plan?.total_failures || 'all'} original attacks against hardened defenses</div>
            <div className="w-48 h-1.5 bg-white/06 rounded-full overflow-hidden">
              <div className="h-full bg-green-500 rounded-full animate-pulse" style={{ width: '60%' }} />
            </div>
          </div>
        )}

        {/* ── PHASE 5: Results ─────────────────────────────────────────────── */}
        {phase === 'results' && retestResult && plan && (
          <div className="p-6 max-w-5xl mx-auto space-y-6">

            {/* Big ISR Comparison */}
            <div className="rounded-2xl border overflow-hidden"
              style={{ borderColor: 'rgba(34,197,94,0.25)', background: 'rgba(34,197,94,0.04)' }}>
              <div className="flex items-center gap-3 px-5 py-3"
                style={{ borderBottom: '1px solid rgba(34,197,94,0.12)', background: 'rgba(34,197,94,0.08)' }}>
                <TrendingDown size={14} className="text-green-400" />
                <span className="text-sm font-bold text-white">Mitigation Results — Before vs After</span>
                <div className={`ml-auto flex items-center gap-2 px-3 py-1 rounded-full border ${GRADE_COLORS[getGrade(retestResult.hardened_isr)]}`}>
                  <span className="text-sm font-bold">Grade {getGrade(retestResult.hardened_isr)}</span>
                </div>
              </div>
              <div className="p-6">
                {/* ISR rings */}
                <div className="flex items-center justify-center gap-10 mb-6">
                  <ISRRing value={retestResult.original_isr} label="Before Mitigation" size={100} />

                  <div className="flex flex-col items-center gap-1">
                    <div className="text-3xl font-black text-green-400">
                      -{retestResult.improvement_pct.toFixed(1)}%
                    </div>
                    <div className="text-[10px] text-gray-500">ISR Reduction</div>
                    <TrendingDown size={20} className="text-green-400" />
                  </div>

                  <ISRRing value={retestResult.hardened_isr} label="After Mitigation" size={100} />
                </div>

                {/* Defense breakdown */}
                <div className="grid grid-cols-3 gap-4 mb-4">
                  {[
                    { label: 'Blocked by Input Guard', val: retestResult.blocked_by_input_guard, color: '#a855f7', bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.2)' },
                    { label: 'Blocked by Hardened Prompt', val: retestResult.blocked_by_prompt_hardening, color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.2)' },
                    { label: 'Blocked by Output Guard', val: retestResult.blocked_by_output_guard, color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.2)' },
                  ].map(({ label, val, color, bg, border }) => (
                    <div key={label} className="rounded-xl text-center py-4 border"
                      style={{ background: bg, borderColor: border }}>
                      <div className="text-2xl font-bold" style={{ color }}>{val}</div>
                      <div className="text-[10px] text-gray-500 mt-1">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Remaining attacks note */}
                {retestResult.per_attack.filter(a => a.after_success).length > 0 && (
                  <div className="p-3 rounded-xl bg-yellow-950/20 border border-yellow-800/30 text-xs text-yellow-300/80 flex items-start gap-2">
                    <AlertTriangle size={12} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                    {retestResult.per_attack.filter(a => a.after_success).length} attacks still bypassed defenses.
                    Consider enabling stricter input filtering or increasing attack coverage in next evaluation.
                  </div>
                )}
              </div>
            </div>

            {/* Side-by-Side Attack Comparison */}
            <div className="rounded-2xl border border-white/08 overflow-hidden">
              <div className="flex items-center gap-3 px-5 py-3 border-b border-white/06 bg-white/02">
                <BarChart2 size={14} className="text-indigo-400" />
                <span className="text-sm font-bold text-white">Side-by-Side Attack Comparison</span>
                <span className="text-[10px] text-gray-500 ml-auto">
                  {retestResult.per_attack.filter(a => a.before_success).length} attacks tested · click any row to expand
                </span>
              </div>

              {/* Legend */}
              <div className="flex items-center gap-4 px-5 py-2 border-b border-white/04 bg-white/01">
                <div className="text-[9px] text-gray-600 w-20">Before</div>
                <div className="w-4" />
                <div className="text-[9px] text-gray-600 w-24">After (Layer)</div>
                <div className="text-[9px] text-gray-600 flex-1">Attack</div>
              </div>

              <div className="p-4 space-y-2">
                {retestResult.per_attack
                  .filter(a => a.before_success || a.after_success)
                  .map((attack, i) => (
                    <AttackCompRow key={i} attack={attack} />
                  ))}
                {retestResult.per_attack.filter(a => !a.before_success && !a.after_success).length > 0 && (
                  <div className="text-center py-3">
                    <button
                      onClick={() => setExpandedCategories(v => !v)}
                      className="text-[10px] text-gray-600 hover:text-gray-400 flex items-center gap-1 mx-auto transition-colors"
                    >
                      {expandedCategories ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                      {expandedCategories ? 'Hide' : 'Show'} {retestResult.per_attack.filter(a => !a.before_success).length} already-safe attacks
                    </button>
                    {expandedCategories && retestResult.per_attack
                      .filter(a => !a.before_success)
                      .map((attack, i) => <AttackCompRow key={`safe-${i}`} attack={attack} />)
                    }
                  </div>
                )}
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex gap-3 pb-4">
              <button
                onClick={() => navigate(`/results/${runId}`)}
                className="flex-1 py-3 rounded-xl text-sm font-semibold text-white flex items-center justify-center gap-2 border border-white/10 hover:bg-white/05 transition-all">
                <BarChart2 size={14} /> View Full Report
              </button>
              <button
                onClick={() => navigate('/risk')}
                className="flex-1 py-3 rounded-xl text-sm font-semibold text-white flex items-center justify-center gap-2 border border-white/10 hover:bg-white/05 transition-all">
                <Shield size={14} /> Risk Dashboard
              </button>
              <button
                onClick={() => navigate('/run')}
                className="flex-1 py-3 rounded-xl text-sm font-bold text-white flex items-center justify-center gap-2 transition-all"
                style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
                <Zap size={14} /> Run New Evaluation
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
