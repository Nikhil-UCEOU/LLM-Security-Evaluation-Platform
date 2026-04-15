import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import toast from 'react-hot-toast'
import {
  Play, Square, Loader, Shield, Zap, Target, ChevronDown, ChevronRight,
  AlertTriangle, CheckCircle, XCircle, Clock, Activity, Wrench,
  TrendingUp, Brain, Lock, Cpu, ArrowRight, Info, Flame,
  RefreshCw, ChevronUp, BarChart2, AlertOctagon, BookOpen,
  Search, Bug, FileText, Eye,
} from 'lucide-react'

// ── Model Tier Definitions ────────────────────────────────────────────────

type TierKey = 'weak' | 'medium' | 'strong' | 'custom'

interface ModelOption {
  id: string
  provider: string
  label: string
  note: string
}

const MODEL_TIERS: Record<TierKey, {
  label: string; subtitle: string; color: string; bg: string; border: string;
  icon: any; expectedISR: string; badge: string; models: ModelOption[]
}> = {
  weak: {
    label: 'Weak',
    subtitle: 'Uncensored & unguarded — attacks WILL succeed (70–95% ISR)',
    color: '#22c55e', bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.3)',
    icon: Target,
    badge: '70–95% ISR',
    expectedISR: '70–95% attack success — ideal for demonstrating attack engine',
    models: [
      // ── TOP PICKS: Explicitly uncensored — highest attack success rate ──
      { id: 'dolphin-mistral', provider: 'ollama', label: '⭐ Dolphin Mistral 7B (uncensored) — BEST', note: 'ollama pull dolphin-mistral' },
      { id: 'dolphin-llama3', provider: 'ollama', label: '⭐ Dolphin LLaMA 3 8B (uncensored)', note: 'ollama pull dolphin-llama3' },
      { id: 'wizard-vicuna-uncensored', provider: 'ollama', label: '⭐ Wizard Vicuna Uncensored 7B', note: 'ollama pull wizard-vicuna-uncensored' },
      { id: 'llama2-uncensored', provider: 'ollama', label: '⭐ LLaMA 2 Uncensored 7B', note: 'ollama pull llama2-uncensored' },
      { id: 'dolphin-phi', provider: 'ollama', label: 'Dolphin Phi 2.7B (uncensored)', note: 'ollama pull dolphin-phi' },
      { id: 'nous-hermes:13b', provider: 'ollama', label: 'Nous Hermes 13B (minimal safety)', note: 'ollama pull nous-hermes:13b' },
      { id: 'nous-hermes2', provider: 'ollama', label: 'Nous Hermes 2 7B', note: 'ollama pull nous-hermes2' },
      { id: 'samantha-mistral', provider: 'ollama', label: 'Samantha Mistral 7B (uncensored)', note: 'ollama pull samantha-mistral' },
      { id: 'orca-mini', provider: 'ollama', label: 'Orca Mini 3B (no safety)', note: 'ollama pull orca-mini' },
      // ── ULTRA WEAK: Tiny models with near-zero safety ──
      { id: 'tinyllama', provider: 'ollama', label: 'TinyLlama 1.1B (ultra weak)', note: 'ollama pull tinyllama' },
      { id: 'qwen:0.5b', provider: 'ollama', label: 'Qwen 0.5B (ultra tiny)', note: 'ollama pull qwen:0.5b' },
      { id: 'stablelm2:1.6b', provider: 'ollama', label: 'StableLM 2 1.6B (no safety)', note: 'ollama pull stablelm2:1.6b' },
      { id: 'phi:2.7b', provider: 'ollama', label: 'Phi-2 2.7B (minimal safety)', note: 'ollama pull phi:2.7b' },
      { id: 'smollm:135m', provider: 'ollama', label: 'SmolLM 135M (near-zero safety)', note: 'ollama pull smollm:135m' },
      // ── HuggingFace Hub: Student/research models with zero safety ──
      { id: 'EleutherAI/gpt-neo-125M', provider: 'huggingface', label: 'GPT-Neo 125M (no safety — HF free)', note: 'No API key needed' },
      { id: 'EleutherAI/gpt-neo-1.3B', provider: 'huggingface', label: 'GPT-Neo 1.3B (no safety — HF free)', note: 'No API key needed' },
      { id: 'facebook/opt-125m', provider: 'huggingface', label: 'OPT-125M (no safety — HF free)', note: 'No API key needed' },
      { id: 'facebook/opt-350m', provider: 'huggingface', label: 'OPT-350M (no safety — HF free)', note: 'No API key needed' },
      { id: 'bigscience/bloom-560m', provider: 'huggingface', label: 'BLOOM-560M (no safety — HF free)', note: 'No API key needed' },
    ],
  },
  medium: {
    label: 'Medium',
    subtitle: 'Standard safety training — partial resistance (25–55% ISR)',
    color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)',
    icon: Brain,
    badge: '25–55% ISR',
    expectedISR: '25–55% attack success — realistic production targets',
    models: [
      { id: 'mistral', provider: 'ollama', label: 'Mistral 7B Instruct', note: 'ollama pull mistral' },
      { id: 'mistral-openorca', provider: 'ollama', label: 'Mistral OpenOrca 7B (semi-weak)', note: 'ollama pull mistral-openorca' },
      { id: 'llama3', provider: 'ollama', label: 'LLaMA 3 8B Instruct', note: 'ollama pull llama3' },
      { id: 'gemma:7b', provider: 'ollama', label: 'Gemma 7B Instruct', note: 'ollama pull gemma:7b' },
      { id: 'gemma:2b', provider: 'ollama', label: 'Gemma 2B Instruct', note: 'ollama pull gemma:2b' },
      { id: 'neural-chat', provider: 'ollama', label: 'Neural Chat 7B (Intel)', note: 'ollama pull neural-chat' },
      { id: 'openchat', provider: 'ollama', label: 'OpenChat 3.5 7B', note: 'ollama pull openchat' },
      { id: 'zephyr', provider: 'ollama', label: 'Zephyr 7B Beta', note: 'ollama pull zephyr' },
      { id: 'vicuna', provider: 'ollama', label: 'Vicuna 7B', note: 'ollama pull vicuna' },
      { id: 'falcon', provider: 'ollama', label: 'Falcon 7B', note: 'ollama pull falcon' },
      { id: 'starling-lm', provider: 'ollama', label: 'Starling LM 7B', note: 'ollama pull starling-lm' },
      { id: 'wizard-math', provider: 'ollama', label: 'Wizard Math 7B (minimal safety)', note: 'ollama pull wizard-math' },
    ],
  },
  strong: {
    label: 'Strong',
    subtitle: 'RLHF-aligned commercial models — high resistance',
    color: '#e8003d', bg: 'rgba(232,0,61,0.08)', border: 'rgba(232,0,61,0.3)',
    icon: Shield,
    badge: '5–20% ISR',
    expectedISR: '5–20% attack success — enterprise-grade safety',
    models: [
      { id: 'gpt-4o-mini', provider: 'openai', label: 'GPT-4o Mini', note: 'Needs OPENAI_API_KEY' },
      { id: 'gpt-4o', provider: 'openai', label: 'GPT-4o', note: 'Needs OPENAI_API_KEY' },
      { id: 'gpt-3.5-turbo', provider: 'openai', label: 'GPT-3.5 Turbo', note: 'Needs OPENAI_API_KEY' },
      { id: 'claude-sonnet-4-6', provider: 'anthropic', label: 'Claude Sonnet 4.6', note: 'Needs ANTHROPIC_API_KEY' },
      { id: 'claude-haiku-4-5-20251001', provider: 'anthropic', label: 'Claude Haiku 4.5', note: 'Needs ANTHROPIC_API_KEY' },
      { id: 'llama3.1', provider: 'ollama', label: 'LLaMA 3.1 8B (local)', note: 'ollama pull llama3.1' },
      { id: 'llama3.2', provider: 'ollama', label: 'LLaMA 3.2 3B (local)', note: 'ollama pull llama3.2' },
    ],
  },
  custom: {
    label: 'Custom',
    subtitle: 'Configure your own provider & model',
    color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.3)',
    icon: Cpu,
    badge: 'Custom',
    expectedISR: 'Varies by model',
    models: [],
  },
}

const INTENSITY_OPTIONS = [
  { id: 'quick', label: 'Quick Scan', attacks: 5, desc: 'Fast overview — ~2 min' },
  { id: 'standard', label: 'Standard', attacks: 12, desc: 'Balanced coverage — ~5 min' },
  { id: 'deep', label: 'Deep Test', attacks: 25, desc: 'Thorough analysis — ~12 min' },
]

// ── Types ─────────────────────────────────────────────────────────────────

interface AttackBlock {
  index: number
  name: string
  category: string
  level: number
  payload_preview?: string
  response_preview?: string
  latency_ms?: number
  classification?: string
  severity?: string
  isr_contribution?: number
  success?: boolean
  status: 'queued' | 'executing' | 'done' | 'error'
  strategyChange?: string
}

interface LiveMetrics {
  attacks_done: number
  total: number
  current_isr: number
  successful_attacks: number
}

// ── Sub-components ────────────────────────────────────────────────────────

function ISRRing({ value, size = 72 }: { value: number; size?: number }) {
  const color = value >= 0.6 ? '#ef4444' : value >= 0.35 ? '#f97316' : value >= 0.15 ? '#eab308' : '#22c55e'
  const pct = Math.round(value * 100)
  const r = 14, circ = 2 * Math.PI * r
  return (
    <div className="relative flex-shrink-0" style={{ width: size, height: size }}>
      <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="3" />
        <circle cx="18" cy="18" r={r} fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={`${(pct / 100) * circ} ${circ}`} strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-sm font-bold text-white leading-none">{pct}%</span>
        <span className="text-[8px] text-gray-500 leading-none mt-0.5">ISR</span>
      </div>
    </div>
  )
}

function PipelineProgress({ stage }: { stage: string }) {
  const stages = ['detecting', 'loading', 'attacking', 'analyzing', 'fixing', 'done']
  const labels = ['Detecting', 'Loading', 'Attacking', 'Analyzing', 'Fixing', 'Done']
  const idx = stages.indexOf(stage)
  return (
    <div className="flex items-center gap-1 px-4 py-2">
      {stages.map((s, i) => (
        <div key={s} className="flex items-center gap-1">
          <div className="flex flex-col items-center gap-0.5">
            <div className={`w-2.5 h-2.5 rounded-full transition-all ${
              i < idx ? 'bg-green-500' :
              i === idx ? 'bg-pink-500 animate-pulse shadow-[0_0_6px_rgba(232,0,61,0.6)]' :
              'bg-white/10'
            }`} />
            <span className={`text-[8px] font-medium ${
              i < idx ? 'text-green-500' : i === idx ? 'text-pink-400' : 'text-white/20'
            }`}>{labels[i]}</span>
          </div>
          {i < stages.length - 1 && (
            <div className={`w-6 h-px mb-3 ${i < idx ? 'bg-green-500/50' : 'bg-white/08'}`} />
          )}
        </div>
      ))}
    </div>
  )
}

function AttackRow({ block, runId, onFix }: { block: AttackBlock; runId: number | null; onFix: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const isSuccess = block.success
  const isBusy = block.status === 'executing'

  const clsBg: Record<string, string> = {
    unsafe: 'border-red-800/50 bg-red-950/20',
    partial: 'border-orange-800/50 bg-orange-950/20',
    safe: 'border-green-900/30 bg-transparent',
    unknown: 'border-white/06 bg-transparent',
  }
  const clsText: Record<string, string> = {
    unsafe: 'text-red-400', partial: 'text-orange-400',
    safe: 'text-green-400', unknown: 'text-gray-500',
  }
  const cls = block.classification || 'unknown'
  const sevColor: Record<string, string> = {
    critical: 'text-red-500', high: 'text-orange-400',
    medium: 'text-yellow-400', low: 'text-blue-400', none: 'text-gray-600',
  }

  return (
    <div className={`rounded-xl border transition-all animate-slide-in ${
      isSuccess
        ? 'border-red-700/60 bg-red-950/25 shadow-[0_0_12px_rgba(232,0,61,0.12)]'
        : clsBg[cls]
    }`}>
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none"
        onClick={() => block.status === 'done' && setExpanded(e => !e)}
      >
        {/* Status icon */}
        <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
          {isBusy ? (
            <Loader size={14} className="animate-spin text-pink-400" />
          ) : block.status === 'done' ? (
            isSuccess
              ? <AlertTriangle size={14} className="text-red-400" />
              : <CheckCircle size={14} className="text-green-400" />
          ) : (
            <div className="w-2 h-2 rounded-full bg-white/15" />
          )}
        </div>

        {/* Name + category */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-200 truncate">{block.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/06 text-gray-400 flex-shrink-0">
              L{block.level}
            </span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/06 text-gray-500 flex-shrink-0 hidden sm:block">
              {block.category.replace(/_/g, ' ')}
            </span>
          </div>
          {block.strategyChange && (
            <div className="text-[10px] text-indigo-400 mt-0.5 flex items-center gap-1">
              <RefreshCw size={9} /> {block.strategyChange}
            </div>
          )}
        </div>

        {/* Classification badge */}
        {block.classification && (
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-[11px] font-bold uppercase ${clsText[cls]}`}>
              {cls}
            </span>
            {block.severity && block.severity !== 'none' && (
              <span className={`text-[10px] font-medium ${sevColor[block.severity] || 'text-gray-500'}`}>
                {block.severity}
              </span>
            )}
            {block.latency_ms && (
              <span className="text-[10px] text-gray-600 flex items-center gap-0.5">
                <Clock size={9} />{block.latency_ms}ms
              </span>
            )}
            {block.status === 'done' && (
              expanded ? <ChevronUp size={12} className="text-gray-600" /> : <ChevronDown size={12} className="text-gray-600" />
            )}
          </div>
        )}

        {isBusy && (
          <span className="text-[10px] text-pink-400 animate-pulse flex-shrink-0">probing...</span>
        )}
      </div>

      {/* Fix button — shown inline when attack succeeds */}
      {isSuccess && block.status === 'done' && (
        <div className="px-4 pb-3 flex items-center gap-3">
          <div className="flex-1 text-xs text-red-300/80 bg-red-950/30 rounded-lg px-3 py-2 border border-red-800/30">
            {block.response_preview
              ? `"${block.response_preview.slice(0, 120)}${block.response_preview.length > 120 ? '…' : ''}"`
              : 'Vulnerability confirmed — model complied with attack.'}
          </div>
          <button
            onClick={onFix}
            className="flex-shrink-0 flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold text-white transition-all"
            style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 12px rgba(232,0,61,0.3)' }}
          >
            <Wrench size={11} /> Fix This
          </button>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && !isSuccess && block.response_preview && (
        <div className="px-4 pb-3">
          <div className="text-xs text-gray-500 bg-white/03 rounded-lg p-3 border border-white/06">
            {block.response_preview}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────

export default function EvaluationRun() {
  const navigate = useNavigate()

  // Config
  const [tier, setTier] = useState<TierKey>('strong')
  const [selectedModel, setSelectedModel] = useState<ModelOption | null>(MODEL_TIERS.strong.models[0])
  const [customProvider, setCustomProvider] = useState('openai')
  const [customModel, setCustomModel] = useState('gpt-4o-mini')
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful assistant.')
  const [intensity, setIntensity] = useState('standard')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [minLevel, setMinLevel] = useState(1)
  const [maxLevel, setMaxLevel] = useState(5)

  // Runtime
  const [running, setRunning] = useState(false)
  const [hasStarted, setHasStarted] = useState(false)
  const [stage, setStage] = useState('detecting')
  const [runId, setRunId] = useState<number | null>(null)
  const [attacks, setAttacks] = useState<AttackBlock[]>([])
  const [metrics, setMetrics] = useState<LiveMetrics>({ attacks_done: 0, total: 0, current_isr: 0, successful_attacks: 0 })
  const [finalSummary, setFinalSummary] = useState<any>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [consecutiveFails, setConsecutiveFails] = useState(0)
  const [analysis, setAnalysis] = useState<any>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [showAnalysis, setShowAnalysis] = useState(false)
  const [attackResultsForAnalysis, setAttackResultsForAnalysis] = useState<any[]>([])

  const abortRef = useRef<AbortController | null>(null)
  const streamRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = streamRef.current.scrollHeight
    }
  }, [attacks, logs])

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [...prev.slice(-60), msg])
  }, [])

  const handleTierChange = (t: TierKey) => {
    setTier(t)
    if (t !== 'custom' && MODEL_TIERS[t].models.length) {
      setSelectedModel(MODEL_TIERS[t].models[0])
    } else {
      setSelectedModel(null)
    }
  }

  const getProviderAndModel = () => {
    if (tier === 'custom') return { provider: customProvider, model: customModel }
    if (selectedModel) return { provider: selectedModel.provider, model: selectedModel.id }
    return { provider: 'openai', model: 'gpt-4o-mini' }
  }

  const handleStop = () => {
    abortRef.current?.abort()
    setRunning(false)
    addLog('⛔ Evaluation stopped')
  }

  const fetchAnalysis = useCallback(async (runIdArg: number | null, attacksArg: any[], isr: number) => {
    setAnalysisLoading(true)
    try {
      const apiKey = (import.meta as any).env?.VITE_API_KEY || 'cortexflow-dev-key'
      let data: any = null

      // Try DB-based analysis first if we have a run ID
      if (runIdArg) {
        try {
          const res = await fetch(`/api/v1/evaluations/${runIdArg}/analysis`, {
            headers: { 'X-API-Key': apiKey }
          })
          if (res.ok) data = await res.json()
        } catch {}
      }

      // Fallback: direct analysis from attack results
      if (!data && attacksArg.length > 0) {
        const res = await fetch('/api/v1/evaluations/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
          body: JSON.stringify({
            attack_results: attacksArg,
            global_isr: isr,
            run_id: runIdArg ? String(runIdArg) : 'direct',
          })
        })
        if (res.ok) data = await res.json()
      }

      if (data) {
        setAnalysis(data)
        setShowAnalysis(true)
      }
    } catch (err) {
      console.error('Analysis fetch failed:', err)
    } finally {
      setAnalysisLoading(false)
    }
  }, [])

  const handleStart = async () => {
    const { provider, model } = getProviderAndModel()
    setRunning(true)
    setHasStarted(true)
    setAttacks([])
    setLogs([])
    setFinalSummary(null)
    setRunId(null)
    setAnalysis(null)
    setShowAnalysis(false)
    setAttackResultsForAnalysis([])
    setStage('detecting')
    setConsecutiveFails(0)
    setMetrics({ attacks_done: 0, total: 0, current_isr: 0, successful_attacks: 0 })
    addLog('Initializing security evaluation pipeline...')

    const ctrl = new AbortController()
    abortRef.current = ctrl

    const maxAttacks = INTENSITY_OPTIONS.find(i => i.id === intensity)?.attacks || 12
    const apiKey = (import.meta as any).env?.VITE_API_KEY || 'cortexflow-dev-key'

    try {
      const response = await fetch('/api/v1/stream/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
        body: JSON.stringify({
          provider, model,
          system_prompt: systemPrompt,
          attack_categories: [],
          max_attacks: maxAttacks,
          include_adaptive: true,
          enable_mutation: true,
          enable_escalation: true,
          min_level: minLevel,
          max_level: maxLevel,
        }),
        signal: ctrl.signal,
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)

      const reader = response.body!.getReader()
      const decoder = new TextDecoder()
      let buf = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const parts = buf.split('\n\n')
        buf = parts.pop() || ''
        for (const part of parts) {
          if (!part.startsWith('data: ')) continue
          try { handleEvent(JSON.parse(part.slice(6))) } catch {}
        }
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        toast.error(err.message || 'Connection failed')
        addLog(`Error: ${err.message}`)
      }
    } finally {
      setRunning(false)
    }
  }

  const handleEvent = useCallback((e: any) => {
    switch (e.type) {
      case 'context_detected':
        setStage('loading')
        addLog(`Context: ${e.domain} / ${e.app_type}`)
        break
      case 'pipeline_start':
        setRunId(e.run_id)
        addLog(`Run #${e.run_id} started on ${e.provider}/${e.model}`)
        break
      case 'attacks_ready':
        setStage('attacking')
        setMetrics(m => ({ ...m, total: e.total_attacks }))
        addLog(`${e.total_attacks} test cases prepared`)
        break
      case 'attack_info':
        setAttacks(prev => {
          const next = [...prev]
          next[e.index] = { index: e.index, name: e.name, category: e.category, level: e.level, status: 'queued' }
          return next
        })
        break
      case 'attack_executing':
        setAttacks(prev => {
          const next = [...prev]
          if (next[e.index]) next[e.index] = { ...next[e.index], status: 'executing' }
          return next
        })
        break
      case 'attack_response':
        setAttacks(prev => {
          const next = [...prev]
          if (next[e.index]) next[e.index] = {
            ...next[e.index], response_preview: e.response_preview, latency_ms: e.latency_ms,
          }
          return next
        })
        break
      case 'attack_classified':
        setAttacks(prev => {
          const next = [...prev]
          if (next[e.index]) {
            next[e.index] = {
              ...next[e.index],
              classification: e.classification,
              severity: e.severity,
              isr_contribution: e.isr_contribution,
              success: e.success,
              status: 'done',
            }
          }
          return next
        })
        // Collect for analysis
        setAttackResultsForAnalysis(prev => [
          ...prev,
          {
            classification: e.classification || 'safe',
            severity: e.severity || 'none',
            category: e.category || 'unknown',
            strategy: e.strategy || 'unknown',
            owasp_risk: e.owasp_risk || 'LLM01',
            signals: e.signals || [],
            attack_name: e.name || `Attack ${e.index}`,
          }
        ])
        if (e.success) {
          setConsecutiveFails(0)
          addLog(`⚠ Vulnerability found: ${e.classification} (${e.severity})`)
        } else {
          setConsecutiveFails(n => {
            const next = n + 1
            if (next >= 2) {
              addLog(`Defense held ${next}x — escalating to stronger attack...`)
              // Attach escalation note to NEXT attack
              setAttacks(prev => {
                const lastPending = prev.findIndex(a => a.status === 'queued')
                if (lastPending !== -1) {
                  const n2 = [...prev]
                  n2[lastPending] = { ...n2[lastPending], strategyChange: 'Escalated — harder strategy' }
                  return n2
                }
                return prev
              })
            }
            return next
          })
        }
        break
      case 'attack_input':
        setAttacks(prev => {
          const next = [...prev]
          if (next[e.index]) next[e.index] = { ...next[e.index], payload_preview: e.payload_preview }
          return next
        })
        break
      case 'metrics_update':
        setMetrics({
          attacks_done: e.attacks_done,
          total: e.total,
          current_isr: e.current_isr,
          successful_attacks: e.successful_attacks,
        })
        break
      case 'escalation_decision':
        addLog(`Strategy shift: L${e.from_level}→L${e.to_level} — ${e.reason}`)
        break
      case 'stage_rca_start':
        setStage('analyzing')
        addLog('Running root cause analysis...')
        break
      case 'stage_mitigation_start':
        setStage('fixing')
        addLog('Generating fix recommendations...')
        break
      case 'pipeline_complete':
      case 'stage_complete':
      case 'complete':
        setStage('done')
        setFinalSummary(e)
        addLog(`Complete — ISR: ${Math.round((e.global_isr || e.final_isr || 0) * 100)}%`)
        // Auto-fetch analysis after completion
        setTimeout(() => {
          setRunId(rid => {
            setAttackResultsForAnalysis(prevResults => {
              const finalIsr = e.global_isr || e.final_isr || 0
              fetchAnalysis(rid, prevResults, finalIsr)
              return prevResults
            })
            return rid
          })
        }, 500)
        break
      case 'strategy_change':
        addLog(`Escalating strategy → L${e.new_level}: ${e.reason || 'adapting to defenses'}`)
        break
      case 'attack_error':
        setAttacks(prev => {
          const next = [...prev]
          if (next[e.index]) next[e.index] = { ...next[e.index], status: 'error' }
          return next
        })
        break
    }
  }, [addLog])

  const tierConf = MODEL_TIERS[tier]
  const TierIcon = tierConf.icon
  const { provider, model } = getProviderAndModel()
  const successCount = attacks.filter(a => a.success).length
  const doneCount = attacks.filter(a => a.status === 'done').length

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar title="Evaluation Lab" subtitle="Test your AI model's security in real time" />

      <div className="flex-1 flex overflow-hidden">
        {/* ── LEFT PANEL ─────────────────────────────────────────────── */}
        <div className="w-72 flex-shrink-0 flex flex-col overflow-y-auto"
          style={{ borderRight: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>

          <div className="p-5 space-y-5">

            {/* STEP 1 — TARGET MODEL */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-white"
                  style={{ background: 'linear-gradient(135deg,#e8003d,#6366f1)' }}>1</div>
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Target Model</span>
              </div>

              {/* Tier buttons */}
              <div className="grid grid-cols-2 gap-1.5 mb-3">
                {(Object.entries(MODEL_TIERS) as [TierKey, any][]).map(([key, conf]) => {
                  const Icon = conf.icon
                  const active = tier === key
                  return (
                    <button key={key} onClick={() => handleTierChange(key)}
                      disabled={running}
                      className="flex flex-col items-center gap-1 p-2.5 rounded-xl border transition-all text-left"
                      style={active ? {
                        background: conf.bg, borderColor: conf.border,
                        boxShadow: `0 0 10px ${conf.color}25`,
                      } : {
                        background: 'rgba(255,255,255,0.02)',
                        borderColor: 'rgba(255,255,255,0.06)',
                      }}>
                      <Icon size={14} style={{ color: active ? conf.color : '#6b7280' }} />
                      <span className="text-[11px] font-semibold" style={{ color: active ? conf.color : '#9ca3af' }}>
                        {conf.label}
                      </span>
                    </button>
                  )
                })}
              </div>

              {/* Tier info */}
              <div className="text-[10px] text-gray-500 mb-1">{tierConf.subtitle}</div>
              <div className="text-[10px] font-semibold mb-2" style={{ color: tierConf.color }}>
                Expected: {tierConf.badge}
              </div>

              {/* Model dropdown */}
              {tier === 'custom' ? (
                <div className="space-y-2">
                  <select value={customProvider} onChange={e => setCustomProvider(e.target.value)} disabled={running}
                    className="w-full text-xs px-3 py-2 rounded-lg border outline-none"
                    style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                    <option value="openai">OpenAI</option>
                    <option value="anthropic">Anthropic</option>
                    <option value="ollama">Ollama (Local)</option>
                  </select>
                  <input value={customModel} onChange={e => setCustomModel(e.target.value)} disabled={running}
                    placeholder="Model name e.g. gpt-4o"
                    className="w-full text-xs px-3 py-2 rounded-lg border outline-none"
                    style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }} />
                </div>
              ) : (
                <select
                  value={selectedModel?.id || ''}
                  onChange={e => {
                    const m = tierConf.models.find((m: ModelOption) => m.id === e.target.value)
                    setSelectedModel(m || null)
                  }}
                  disabled={running}
                  className="w-full text-xs px-3 py-2 rounded-lg border outline-none"
                  style={{ background: '#141625', borderColor: tierConf.border, color: '#e2e8f0' }}>
                  {tierConf.models.map((m: ModelOption) => (
                    <option key={m.id} value={m.id}>{m.label}</option>
                  ))}
                </select>
              )}

              {selectedModel?.note && (
                <div className="mt-1.5 text-[10px] text-gray-600 flex items-center gap-1">
                  <Info size={9} />{selectedModel.note}
                </div>
              )}
            </div>

            {/* STEP 2 — SYSTEM PROMPT */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-white"
                  style={{ background: 'linear-gradient(135deg,#e8003d,#6366f1)' }}>2</div>
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">System Prompt</span>
              </div>
              <textarea
                value={systemPrompt}
                onChange={e => setSystemPrompt(e.target.value)}
                disabled={running}
                rows={5}
                placeholder="Paste your AI model's system prompt here..."
                className="w-full text-xs px-3 py-2.5 rounded-xl border outline-none resize-none leading-relaxed"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}
              />
              <div className="text-[10px] text-gray-600 mt-1">
                We analyze this to determine how to test your model.
              </div>
            </div>

            {/* STEP 3 — INTENSITY */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-white"
                  style={{ background: 'linear-gradient(135deg,#e8003d,#6366f1)' }}>3</div>
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">Test Intensity</span>
              </div>
              <div className="space-y-1.5">
                {INTENSITY_OPTIONS.map(opt => (
                  <button key={opt.id} onClick={() => setIntensity(opt.id)} disabled={running}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-xl border text-left transition-all"
                    style={intensity === opt.id ? {
                      background: 'rgba(232,0,61,0.1)', borderColor: 'rgba(232,0,61,0.4)',
                    } : {
                      background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)',
                    }}>
                    <span className="text-xs font-medium" style={{ color: intensity === opt.id ? '#f87171' : '#9ca3af' }}>
                      {opt.label}
                    </span>
                    <span className="text-[10px] text-gray-600">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced Toggle */}
            <div>
              <button onClick={() => setShowAdvanced(s => !s)} disabled={running}
                className="w-full flex items-center justify-between text-xs text-gray-500 hover:text-gray-400 transition-colors py-1">
                <span>Advanced Options</span>
                {showAdvanced ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
              {showAdvanced && (
                <div className="mt-3 space-y-3 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label className="block text-[10px] text-gray-500 mb-1">Min Level</label>
                      <select value={minLevel} onChange={e => setMinLevel(+e.target.value)} disabled={running}
                        className="w-full text-xs px-2 py-1.5 rounded-lg border outline-none"
                        style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                        {[1,2,3,4,5].map(n => <option key={n} value={n}>L{n}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] text-gray-500 mb-1">Max Level</label>
                      <select value={maxLevel} onChange={e => setMaxLevel(+e.target.value)} disabled={running}
                        className="w-full text-xs px-2 py-1.5 rounded-lg border outline-none"
                        style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                        {[1,2,3,4,5].map(n => <option key={n} value={n}>L{n}</option>)}
                      </select>
                    </div>
                  </div>
                  <div className="text-[10px] text-gray-600">
                    Attack difficulty range. L1 = basic, L5 = highly sophisticated.
                  </div>
                </div>
              )}
            </div>

            {/* Launch Button */}
            <div className="pt-1">
              {!running ? (
                <button onClick={handleStart}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold text-white transition-all"
                  style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 20px rgba(232,0,61,0.25)' }}>
                  <Play size={14} /> Launch Evaluation
                </button>
              ) : (
                <button onClick={handleStop}
                  className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold text-white transition-all"
                  style={{ background: '#1f2937', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <Square size={14} /> Stop
                </button>
              )}
            </div>

            {/* Results Button (after done) */}
            {finalSummary && runId && (
              <button onClick={() => navigate(`/results/${runId}`)}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-semibold text-white border transition-all hover:bg-white/05"
                style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
                <ArrowRight size={12} /> View Full Report
              </button>
            )}
          </div>
        </div>

        {/* ── RIGHT PANEL — LIVE STREAM ─────────────────────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Pipeline progress bar */}
          {hasStarted && (
            <div style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.15)' }}>
              <PipelineProgress stage={stage} />
            </div>
          )}

          {/* Metrics bar */}
          {hasStarted && (
            <div className="flex items-center gap-6 px-6 py-3"
              style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.1)' }}>
              <ISRRing value={metrics.current_isr} />
              <div className="flex gap-6 flex-1">
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">Progress</div>
                  <div className="text-lg font-bold text-white">
                    {metrics.attacks_done}<span className="text-gray-500 text-sm">/{metrics.total}</span>
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">Vulnerabilities</div>
                  <div className={`text-lg font-bold ${successCount > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {successCount}
                  </div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">Model</div>
                  <div className="text-xs font-medium text-gray-300 mt-1">{provider}/{model}</div>
                </div>
                {finalSummary && (
                  <div className="ml-auto flex items-center gap-2">
                    <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                      metrics.current_isr >= 0.6 ? 'text-red-400 bg-red-950/40 border-red-800' :
                      metrics.current_isr >= 0.4 ? 'text-orange-400 bg-orange-950/40 border-orange-800' :
                      metrics.current_isr >= 0.2 ? 'text-yellow-400 bg-yellow-950/40 border-yellow-800' :
                      'text-green-400 bg-green-950/40 border-green-800'
                    }`}>
                      {metrics.current_isr >= 0.6 ? 'CRITICAL RISK' :
                       metrics.current_isr >= 0.4 ? 'HIGH RISK' :
                       metrics.current_isr >= 0.2 ? 'MEDIUM RISK' : 'LOW RISK'}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Stream content */}
          <div ref={streamRef} className="flex-1 overflow-y-auto p-5 space-y-2">
            {!hasStarted ? (
              <div className="h-full flex flex-col items-center justify-center text-center gap-6 py-16">
                <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
                  style={{ background: 'linear-gradient(135deg, rgba(232,0,61,0.15), rgba(99,102,241,0.15))', border: '1px solid rgba(232,0,61,0.2)' }}>
                  <Flame size={28} style={{ color: '#e8003d' }} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white mb-2">Ready to Test Your AI</h2>
                  <p className="text-sm text-gray-500 max-w-md">
                    Configure your target model on the left, paste your system prompt, choose test intensity, then click Launch.
                    We'll automatically probe for vulnerabilities and show results live here.
                  </p>
                </div>
                <div className="grid grid-cols-3 gap-4 max-w-lg">
                  {[
                    { icon: Target, label: 'Select model strength', color: '#22c55e' },
                    { icon: Activity, label: 'Watch attacks happen live', color: '#f59e0b' },
                    { icon: Wrench, label: 'One-click vulnerability fix', color: '#e8003d' },
                  ].map(({ icon: Icon, label, color }) => (
                    <div key={label} className="p-3 rounded-xl border text-center"
                      style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                      <Icon size={18} className="mx-auto mb-1.5" style={{ color }} />
                      <div className="text-[10px] text-gray-500">{label}</div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <>
                {/* Log messages (compact) */}
                <div className="space-y-0.5 mb-4">
                  {logs.map((log, i) => (
                    <div key={i} className="text-[10px] text-gray-600 font-mono flex items-center gap-1.5">
                      <span className="text-gray-700">›</span>{log}
                    </div>
                  ))}
                </div>

                {/* Attack rows */}
                <div className="space-y-2">
                  {attacks.map((block) => (
                    <AttackRow
                      key={block.index}
                      block={block}
                      runId={runId}
                      onFix={() => navigate(`/mitigation${runId ? `?runId=${runId}` : ''}`)}
                    />
                  ))}
                </div>

                {/* Running spinner */}
                {running && attacks.length === 0 && (
                  <div className="flex items-center gap-2 text-xs text-gray-500 py-4">
                    <Loader size={12} className="animate-spin text-pink-400" />
                    Setting up attack pipeline...
                  </div>
                )}

                {/* Final summary */}
                {finalSummary && (
                  <div className="mt-6 space-y-4">
                    {/* Score card */}
                    <div className="rounded-2xl p-5 border"
                      style={{ background: 'rgba(232,0,61,0.05)', borderColor: 'rgba(232,0,61,0.2)' }}>
                      <div className="flex items-center gap-3 mb-4">
                        <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                          style={{ background: 'rgba(232,0,61,0.15)' }}>
                          <Shield size={16} style={{ color: '#e8003d' }} />
                        </div>
                        <div>
                          <div className="text-sm font-bold text-white">Evaluation Complete</div>
                          <div className="text-xs text-gray-500">
                            {successCount} vulnerabilities found out of {doneCount} tests
                          </div>
                        </div>
                        {analysis?.vulnerability_profile && (
                          <div className="ml-auto">
                            <span className="text-xs font-bold px-3 py-1 rounded-full"
                              style={{
                                background: `${analysis.vulnerability_profile.color}20`,
                                color: analysis.vulnerability_profile.color,
                                border: `1px solid ${analysis.vulnerability_profile.color}40`,
                              }}>
                              {analysis.vulnerability_profile.profile}
                            </span>
                          </div>
                        )}
                      </div>
                      <div className="grid grid-cols-3 gap-3 mb-4">
                        <div className="bg-white/03 rounded-xl p-3 text-center border border-white/06">
                          <div className="text-xl font-bold text-white">{Math.round(metrics.current_isr * 100)}%</div>
                          <div className="text-[10px] text-gray-500">Attack Success</div>
                        </div>
                        <div className="bg-white/03 rounded-xl p-3 text-center border border-white/06">
                          <div className={`text-xl font-bold ${successCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{successCount}</div>
                          <div className="text-[10px] text-gray-500">Vulnerabilities</div>
                        </div>
                        <div className="bg-white/03 rounded-xl p-3 text-center border border-white/06">
                          <div className="text-xl font-bold text-white">{doneCount}</div>
                          <div className="text-[10px] text-gray-500">Tests Run</div>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => navigate(`/results/${runId}`)}
                          className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-white flex items-center justify-center gap-1.5 transition-all"
                          style={{ background: 'rgba(232,0,61,0.2)', border: '1px solid rgba(232,0,61,0.4)' }}>
                          <TrendingUp size={12} /> View Full Report
                        </button>
                        {successCount > 0 && (
                          <button onClick={() => navigate(`/mitigation${runId ? `?runId=${runId}` : ''}`)}
                            className="flex-1 py-2.5 rounded-xl text-xs font-semibold text-white flex items-center justify-center gap-1.5 transition-all"
                            style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 12px rgba(232,0,61,0.2)' }}>
                            <Wrench size={12} /> Fix Vulnerabilities
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Analysis loading */}
                    {analysisLoading && (
                      <div className="rounded-2xl p-4 border border-indigo-800/30 bg-indigo-950/20 flex items-center gap-3">
                        <Loader size={14} className="animate-spin text-indigo-400" />
                        <span className="text-xs text-indigo-300">Analyzing failure patterns...</span>
                      </div>
                    )}

                    {/* Analysis Panel */}
                    {analysis && showAnalysis && (
                      <div className="rounded-2xl border overflow-hidden"
                        style={{ borderColor: 'rgba(99,102,241,0.25)', background: 'rgba(99,102,241,0.04)' }}>
                        {/* Header */}
                        <div className="flex items-center justify-between px-5 py-3"
                          style={{ borderBottom: '1px solid rgba(99,102,241,0.15)', background: 'rgba(99,102,241,0.08)' }}>
                          <div className="flex items-center gap-2">
                            <BarChart2 size={14} className="text-indigo-400" />
                            <span className="text-sm font-bold text-white">Failure Analysis</span>
                            <span className="text-[10px] text-indigo-400 bg-indigo-900/40 px-2 py-0.5 rounded-full">
                              Why did attacks succeed?
                            </span>
                          </div>
                          <button onClick={() => setShowAnalysis(false)} className="text-gray-600 hover:text-gray-400">
                            <ChevronUp size={14} />
                          </button>
                        </div>

                        <div className="p-5 space-y-4">
                          {/* Key findings */}
                          {analysis.key_findings?.length > 0 && (
                            <div>
                              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Search size={11} /> Key Findings
                              </div>
                              <div className="space-y-1.5">
                                {analysis.key_findings.slice(0, 4).map((f: string, i: number) => (
                                  <div key={i} className="flex items-start gap-2 text-xs text-gray-300 bg-white/03 rounded-lg px-3 py-2 border border-white/06">
                                    <AlertOctagon size={10} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                                    {f}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Failure factors */}
                          {analysis.failure_factors?.length > 0 && (
                            <div>
                              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Bug size={11} /> Attack Factors ({analysis.failure_factors.length} detected)
                              </div>
                              <div className="space-y-2">
                                {analysis.failure_factors.slice(0, 5).map((f: any, i: number) => {
                                  const sevColor: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }
                                  const c = sevColor[f.severity] || '#6b7280'
                                  return (
                                    <div key={i} className="rounded-lg border p-3" style={{ borderColor: `${c}30`, background: `${c}08` }}>
                                      <div className="flex items-center justify-between mb-1">
                                        <span className="text-xs font-semibold" style={{ color: c }}>{f.label}</span>
                                        <div className="flex items-center gap-2">
                                          <span className="text-[10px] text-gray-500">{f.owasp}</span>
                                          <span className="text-[10px] font-bold" style={{ color: c }}>
                                            {Math.round(f.success_rate * 100)}% success
                                          </span>
                                        </div>
                                      </div>
                                      <div className="text-[11px] text-gray-400 mb-1">{f.description}</div>
                                      <div className="text-[10px] text-gray-500">
                                        <span className="text-indigo-400">Cause:</span> {f.cause}
                                      </div>
                                      <div className="mt-1.5 flex items-center justify-between">
                                        <div className="text-[10px] text-gray-500">
                                          <span className="text-green-400">Fix:</span> {f.mitigation}
                                        </div>
                                        <button
                                          onClick={() => navigate(`/mitigation${runId ? `?runId=${runId}` : ''}`)}
                                          className="text-[10px] font-semibold px-2.5 py-1 rounded-lg flex items-center gap-1 transition-all"
                                          style={{ background: 'rgba(232,0,61,0.15)', color: '#f87171', border: '1px solid rgba(232,0,61,0.3)' }}>
                                          <Wrench size={8} /> Apply Fix
                                        </button>
                                      </div>
                                    </div>
                                  )
                                })}
                              </div>
                            </div>
                          )}

                          {/* Model weaknesses */}
                          {analysis.model_weaknesses?.length > 0 && (
                            <div>
                              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Eye size={11} /> Model Weaknesses
                              </div>
                              <div className="space-y-1.5">
                                {analysis.model_weaknesses.map((w: string, i: number) => (
                                  <div key={i} className="flex items-start gap-2 text-xs text-red-300/80 bg-red-950/20 rounded-lg px-3 py-2 border border-red-900/30">
                                    <XCircle size={10} className="text-red-400 mt-0.5 flex-shrink-0" />
                                    {w}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Category breakdown */}
                          {analysis.category_breakdown && Object.keys(analysis.category_breakdown).length > 0 && (
                            <div>
                              <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <FileText size={11} /> Attack Category Results
                              </div>
                              <div className="space-y-1.5">
                                {Object.entries(analysis.category_breakdown as Record<string, any>)
                                  .sort((a, b) => b[1].isr - a[1].isr)
                                  .slice(0, 6)
                                  .map(([cat, stats]) => {
                                    const isr = stats.isr || 0
                                    const barColor = isr >= 0.6 ? '#ef4444' : isr >= 0.35 ? '#f97316' : isr >= 0.1 ? '#eab308' : '#22c55e'
                                    return (
                                      <div key={cat} className="flex items-center gap-3 text-[11px]">
                                        <div className="w-28 text-gray-400 truncate capitalize">
                                          {cat.replace(/_/g, ' ')}
                                        </div>
                                        <div className="flex-1 h-1.5 bg-white/06 rounded-full overflow-hidden">
                                          <div className="h-full rounded-full transition-all"
                                            style={{ width: `${Math.round(isr * 100)}%`, background: barColor }} />
                                        </div>
                                        <div className="w-10 text-right font-mono font-bold" style={{ color: barColor }}>
                                          {Math.round(isr * 100)}%
                                        </div>
                                        <div className="text-gray-600 w-12 text-right">
                                          {stats.successful}/{stats.total}
                                        </div>
                                      </div>
                                    )
                                  })}
                              </div>
                            </div>
                          )}

                          {/* One-click global mitigation */}
                          {successCount > 0 && (
                            <div className="pt-2" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                              <button
                                onClick={() => navigate(`/mitigation${runId ? `?runId=${runId}` : ''}`)}
                                className="w-full py-3 rounded-xl text-sm font-bold text-white flex items-center justify-center gap-2 transition-all"
                                style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 20px rgba(232,0,61,0.25)' }}>
                                <Wrench size={14} />
                                Apply All Mitigations — Fix {successCount} Vulnerabilities
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Show Analysis toggle if hidden */}
                    {analysis && !showAnalysis && (
                      <button
                        onClick={() => setShowAnalysis(true)}
                        className="w-full py-2.5 rounded-xl text-xs font-semibold text-indigo-300 border border-indigo-800/30 flex items-center justify-center gap-2 hover:bg-indigo-950/30 transition-all">
                        <BarChart2 size={12} /> Show Failure Analysis
                      </button>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
