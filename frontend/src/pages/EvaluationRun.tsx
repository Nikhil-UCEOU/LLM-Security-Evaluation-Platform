import { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import toast from 'react-hot-toast'
import {
  Play, Square, Loader, Brain, Shield, Zap, Target, ChevronDown,
  AlertTriangle, CheckCircle, XCircle, Clock, Cpu, TrendingUp,
  FileText, Code, Globe, Activity, Layers, Eye, RefreshCw,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────

type AppType = 'chatbot' | 'rag' | 'agent' | 'hybrid' | 'multi_turn_chatbot'
type Domain = 'general' | 'finance' | 'healthcare' | 'legal' | 'hr' | 'security'
type AttackMode = 'standard' | 'aggressive' | 'stealth' | 'adaptive'

interface StreamEvent {
  type: string
  [key: string]: any
}

interface AttackBlock {
  index: number
  name: string
  category: string
  level: number
  attack_type: string
  domain: string
  risk_score: number
  payload_preview?: string
  full_payload?: string
  response_preview?: string
  latency_ms?: number
  tokens_used?: number
  classification?: string
  severity?: string
  isr_contribution?: number
  status: 'pending' | 'queued' | 'executing' | 'responded' | 'classified' | 'done' | 'error'
  error?: string
}

interface LiveMetrics {
  attacks_done: number
  total: number
  current_isr: number
  successful_attacks: number
  current_level: number
}

interface ContextResult {
  domain: Domain
  app_type: AppType
  domain_confidence: number
  app_type_confidence: number
  detected_signals: string[]
  recommended_categories: string[]
}

// ── Constants ─────────────────────────────────────────────────────────────

const PROVIDERS = [
  { id: 'openai', label: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'] },
  { id: 'anthropic', label: 'Anthropic', models: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001'] },
  { id: 'ollama', label: 'Ollama (Local)', models: ['llama3', 'mistral', 'phi3', 'codellama'] },
]

const ALL_CATEGORIES = [
  'prompt_injection', 'jailbreak', 'role_play', 'indirect_injection',
  'context_manipulation', 'multi_turn', 'payload_encoding', 'rag_poisoning',
  'api_abuse', 'cognitive', 'strategy_based',
]

const ATTACK_MODES: { id: AttackMode; label: string; desc: string }[] = [
  { id: 'standard', label: 'Standard', desc: 'Balanced across all categories' },
  { id: 'aggressive', label: 'Aggressive', desc: 'Max attacks, all levels' },
  { id: 'stealth', label: 'Stealth', desc: 'Low-visibility, encoded payloads' },
  { id: 'adaptive', label: 'Adaptive', desc: 'RL-guided, escalates on success' },
]

const APP_TYPE_ICONS: Record<string, any> = {
  chatbot: Brain, rag: FileText, agent: Code, hybrid: Layers, multi_turn_chatbot: Activity,
}

const APP_TYPE_LABELS: Record<string, string> = {
  chatbot: 'Chatbot', rag: 'RAG Application', agent: 'AI Agent',
  hybrid: 'Hybrid (RAG+Agent)', multi_turn_chatbot: 'Multi-Turn Chat',
}

const DOMAIN_LABELS: Record<string, string> = {
  general: 'General', finance: 'Finance', healthcare: 'Healthcare',
  legal: 'Legal', hr: 'Human Resources', security: 'Security',
}

const CLASSIFICATION_COLOR: Record<string, string> = {
  unsafe: 'text-red-400 bg-red-900/30 border-red-800',
  partial: 'text-orange-400 bg-orange-900/30 border-orange-800',
  safe: 'text-green-400 bg-green-900/30 border-green-800',
  unknown: 'text-gray-400 bg-gray-800/50 border-gray-700',
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-500', high: 'text-orange-400',
  medium: 'text-yellow-400', low: 'text-green-400', none: 'text-gray-500',
}

const LEVEL_COLOR: Record<number, string> = {
  1: 'text-green-400 bg-green-900/30',
  2: 'text-cyan-400 bg-cyan-900/30',
  3: 'text-yellow-400 bg-yellow-900/30',
  4: 'text-orange-400 bg-orange-900/30',
  5: 'text-red-400 bg-red-900/30',
}

// ── Helper components ─────────────────────────────────────────────────────

function Toggle({ on, onToggle, label, sub }: { on: boolean; onToggle: () => void; label: string; sub?: string }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <div>
        <div className="text-xs text-gray-300">{label}</div>
        {sub && <div className="text-[10px] text-gray-600">{sub}</div>}
      </div>
      <button
        type="button"
        onClick={onToggle}
        className={`relative w-10 h-5 rounded-full transition-colors flex-shrink-0 ${on ? 'bg-brand-500' : 'bg-gray-700'}`}
      >
        <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-transform shadow ${on ? 'translate-x-5' : 'translate-x-0.5'}`} />
      </button>
    </div>
  )
}

function ISRGauge({ value }: { value: number }) {
  const color = value >= 0.7 ? '#ef4444' : value >= 0.4 ? '#f97316' : value >= 0.2 ? '#eab308' : '#22c55e'
  const pct = Math.round(value * 100)
  return (
    <div className="relative w-20 h-20 flex-shrink-0">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
        <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1f2937" strokeWidth="3" />
        <circle
          cx="18" cy="18" r="15.9" fill="none"
          stroke={color} strokeWidth="3"
          strokeDasharray={`${pct} ${100 - pct}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.5s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-base font-bold text-white">{pct}%</span>
        <span className="text-[9px] text-gray-500">ISR</span>
      </div>
    </div>
  )
}

function StageIndicator({ stages, currentStage }: { stages: string[]; currentStage: string }) {
  const idx = stages.indexOf(currentStage)
  return (
    <div className="flex items-center gap-1">
      {stages.map((s, i) => (
        <div key={s} className="flex items-center gap-1">
          <div className={`w-2 h-2 rounded-full ${
            i < idx ? 'bg-green-500' : i === idx ? 'bg-brand-500 animate-pulse' : 'bg-gray-700'
          }`} />
          {i < stages.length - 1 && <div className={`w-4 h-px ${i < idx ? 'bg-green-500/50' : 'bg-gray-700'}`} />}
        </div>
      ))}
    </div>
  )
}

const PIPELINE_STAGES = ['context', 'attacks', 'evaluate', 'rca', 'mitigate', 'retest', 'learn', 'done']

// ── Main component ────────────────────────────────────────────────────────

export default function EvaluationRun() {
  const navigate = useNavigate()

  // Config state
  const [provider, setProvider] = useState('openai')
  const [model, setModel] = useState('gpt-4o-mini')
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful assistant.')
  const [attackMode, setAttackMode] = useState<AttackMode>('standard')
  const [minLevel, setMinLevel] = useState(1)
  const [maxLevel, setMaxLevel] = useState(5)
  const [maxAttacks, setMaxAttacks] = useState(10)
  const [selectedCategories, setSelectedCategories] = useState<string[]>([])
  const [enableMutation, setEnableMutation] = useState(false)
  const [enableEscalation, setEnableEscalation] = useState(true)
  const [enableMultiTurn, setEnableMultiTurn] = useState(false)
  const [enableStrategy, setEnableStrategy] = useState(false)
  const [documentContent, setDocumentContent] = useState('')
  const [apiSchema, setApiSchema] = useState('')
  const [showHybridInputs, setShowHybridInputs] = useState(false)

  // Runtime state
  const [running, setRunning] = useState(false)
  const [hasStarted, setHasStarted] = useState(false)
  const [pipelineStage, setPipelineStage] = useState('context')
  const [ctx, setCtx] = useState<ContextResult | null>(null)
  const [attacks, setAttacks] = useState<AttackBlock[]>([])
  const [metrics, setMetrics] = useState<LiveMetrics>({ attacks_done: 0, total: 0, current_isr: 0, successful_attacks: 0, current_level: 1 })
  const [finalSummary, setFinalSummary] = useState<any>(null)
  const [stageLogs, setStageLogs] = useState<string[]>([])
  const [expandedAttack, setExpandedAttack] = useState<number | null>(null)

  const abortRef = useRef<AbortController | null>(null)
  const consoleRef = useRef<HTMLDivElement>(null)
  const selectedProvider = PROVIDERS.find(p => p.id === provider)

  // Auto-scroll console
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [attacks, stageLogs])

  const addLog = useCallback((msg: string) => {
    setStageLogs(prev => [...prev.slice(-100), `[${new Date().toLocaleTimeString()}] ${msg}`])
  }, [])

  const toggleCategory = (cat: string) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    )
  }

  const handleStop = () => {
    abortRef.current?.abort()
    setRunning(false)
    addLog('⛔ Evaluation stopped by user')
  }

  const handleStart = async () => {
    setRunning(true)
    setHasStarted(true)
    setAttacks([])
    setStageLogs([])
    setFinalSummary(null)
    setCtx(null)
    setPipelineStage('context')
    addLog('🚀 Initializing evaluation pipeline...')

    const ctrl = new AbortController()
    abortRef.current = ctrl

    // Apply attack mode presets
    let finalMax = maxAttacks
    let finalMin = minLevel
    let finalMax2 = maxLevel
    if (attackMode === 'aggressive') { finalMax = Math.max(maxAttacks, 20); finalMin = 1; finalMax2 = 5 }
    else if (attackMode === 'stealth') { finalMax = Math.min(maxAttacks, 8) }

    const apiKey = (import.meta as any).env?.VITE_API_KEY || 'cortexflow-dev-key'

    try {
      const response = await fetch('/api/v1/stream/evaluate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({
          provider,
          model,
          system_prompt: systemPrompt,
          attack_categories: selectedCategories,
          max_attacks: finalMax,
          include_adaptive: enableMutation,
          document_content: documentContent,
          api_schema: apiSchema,
          enable_mutation: enableMutation,
          enable_escalation: enableEscalation,
          min_level: finalMin,
          max_level: finalMax2,
        }),
        signal: ctrl.signal,
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`)
      }

      const reader = response.body!.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const event: StreamEvent = JSON.parse(line.slice(6))
            handleEvent(event)
          } catch {
            // ignore parse errors
          }
        }
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        toast.error(err.message || 'Streaming failed')
        addLog(`❌ Error: ${err.message}`)
      }
    } finally {
      setRunning(false)
    }
  }

  const handleEvent = (e: StreamEvent) => {
    switch (e.type) {
      case 'context_detected':
        setCtx(e as ContextResult)
        setPipelineStage('attacks')
        addLog(`🔍 Context: domain=${e.domain} (${Math.round(e.domain_confidence * 100)}%), app=${e.app_type}`)
        break

      case 'pipeline_start':
        addLog(`⚙️ Pipeline started — Run #${e.run_id}`)
        break

      case 'attacks_ready':
        setMetrics(m => ({ ...m, total: e.total_attacks }))
        addLog(`📦 ${e.total_attacks} attacks ready (L${e.levels_in_use?.join(', L')})`)
        setPipelineStage('evaluate')
        break

      case 'attack_info':
        setAttacks(prev => {
          const next = [...prev]
          next[e.index] = {
            index: e.index,
            name: e.name,
            category: e.category,
            level: e.level,
            attack_type: e.attack_type,
            domain: e.domain,
            risk_score: e.risk_score,
            status: 'queued',
          }
          return next
        })
        break

      case 'attack_input':
        setAttacks(prev => prev.map((a, i) =>
          i === e.index ? { ...a, payload_preview: e.payload_preview, full_payload: e.full_payload, status: 'queued' } : a
        ))
        break

      case 'attack_executing':
        setAttacks(prev => prev.map((a, i) =>
          i === e.index ? { ...a, status: 'executing' } : a
        ))
        break

      case 'attack_response':
        setAttacks(prev => prev.map((a, i) =>
          i === e.index ? { ...a, response_preview: e.response_preview, latency_ms: e.latency_ms, tokens_used: e.tokens_used, status: 'responded' } : a
        ))
        break

      case 'attack_classified':
        setAttacks(prev => prev.map((a, i) =>
          i === e.index ? {
            ...a,
            classification: e.classification,
            severity: e.severity,
            isr_contribution: e.isr_contribution,
            status: 'done',
          } : a
        ))
        if (e.success) addLog(`🔴 Attack #${e.index + 1} SUCCEEDED (${e.severity})`)
        break

      case 'attack_error':
        setAttacks(prev => prev.map((a, i) =>
          i === e.index ? { ...a, status: 'error', error: e.error } : a
        ))
        break

      case 'metrics_update':
        setMetrics({
          attacks_done: e.attacks_done,
          total: e.total,
          current_isr: e.current_isr,
          successful_attacks: e.successful_attacks,
          current_level: e.current_level,
        })
        break

      case 'escalation_decision':
        addLog(`⬆️ Escalation: L${e.from_level} → L${e.to_level} (${e.reason})`)
        break

      case 'stage_isr':
        addLog(`📊 ISR: ${Math.round(e.global_isr * 100)}% (${e.successful_attacks}/${e.total_attacks})`)
        setPipelineStage('rca')
        break

      case 'stage_rca_start':
        addLog('🧠 Running root cause analysis...')
        break

      case 'stage_rca_done':
        addLog(`✅ RCA done — ${e.root_causes?.length || 0} root causes, ${e.attack_trace_count} attack traces`)
        setPipelineStage('mitigate')
        break

      case 'stage_mitigation_start':
        addLog('🛡️ Generating mitigation strategy...')
        break

      case 'stage_mitigation_done':
        addLog(`✅ Mitigation ready — ${e.guardrail_count} guardrails, strategy: ${e.strategy}`)
        setPipelineStage('retest')
        break

      case 'stage_retest_start':
        addLog('🔁 Re-testing with hardened prompt...')
        break

      case 'stage_retest_done':
        addLog(`✅ Re-test: ISR ${Math.round(e.original_isr * 100)}% → ${Math.round(e.hardened_isr * 100)}% (${e.improvement_pct > 0 ? '+' : ''}${e.improvement_pct.toFixed(1)}% improvement)`)
        setPipelineStage('learn')
        break

      case 'stage_learning_start':
        addLog('💾 Storing insights...')
        break

      case 'stage_learning_done':
        addLog(`✅ Learning engine updated — ${e.entries_stored} entries`)
        setPipelineStage('done')
        break

      case 'complete':
        setFinalSummary(e)
        setRunning(false)
        addLog(`🏁 Pipeline complete! ISR=${Math.round(e.global_isr * 100)}%, improvement=${e.improvement_pct?.toFixed(1)}%`)
        toast.success(`Evaluation complete! ISR: ${Math.round(e.global_isr * 100)}%`)
        break

      case 'error':
        addLog(`❌ Pipeline error: ${e.message}`)
        setRunning(false)
        toast.error(e.message)
        break
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden">
      <TopBar
        title="Evaluation Lab"
        subtitle={hasStarted ? 'Live execution in progress' : 'Configure and launch the enterprise evaluation pipeline'}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* ═══════════════════════════════════════════════════════════════
            LEFT PANEL — Configuration & Control (35%)
        ═══════════════════════════════════════════════════════════════ */}
        <div className="w-[35%] min-w-[320px] border-r border-gray-800 flex flex-col overflow-y-auto">
          <div className="p-4 space-y-4 flex-1">

            {/* ── Model Selection ── */}
            <section>
              <div className="flex items-center gap-2 mb-3">
                <Cpu size={13} className="text-brand-500" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Target LLM</h2>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[10px] text-gray-600 mb-1">Provider</label>
                  <select
                    value={provider}
                    onChange={e => { setProvider(e.target.value); setModel(PROVIDERS.find(p => p.id === e.target.value)?.models[0] || '') }}
                    disabled={running}
                    className="w-full bg-gray-900 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-brand-500"
                  >
                    {PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-[10px] text-gray-600 mb-1">Model</label>
                  <select
                    value={model}
                    onChange={e => setModel(e.target.value)}
                    disabled={running}
                    className="w-full bg-gray-900 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-brand-500"
                  >
                    {selectedProvider?.models.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
              </div>
            </section>

            {/* ── Context Detection Result ── */}
            {ctx && (
              <section className="bg-gray-900 border border-brand-800/50 rounded-xl p-3">
                <div className="flex items-center gap-2 mb-2">
                  <Eye size={12} className="text-brand-500" />
                  <span className="text-[10px] font-bold text-brand-400 uppercase tracking-wide">Auto-Detected Context</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-gray-800/60 rounded-lg p-2">
                    <div className="text-[10px] text-gray-600 mb-0.5">Domain</div>
                    <div className="text-xs font-bold text-white capitalize">{DOMAIN_LABELS[ctx.domain]}</div>
                    <div className="text-[10px] text-gray-600">{Math.round(ctx.domain_confidence * 100)}% confidence</div>
                  </div>
                  <div className="bg-gray-800/60 rounded-lg p-2">
                    <div className="text-[10px] text-gray-600 mb-0.5">App Type</div>
                    <div className="text-xs font-bold text-white">{APP_TYPE_LABELS[ctx.app_type]}</div>
                    <div className="text-[10px] text-gray-600">{Math.round(ctx.app_type_confidence * 100)}% confidence</div>
                  </div>
                </div>
                {ctx.recommended_categories.length > 0 && (
                  <div className="mt-2">
                    <div className="text-[10px] text-gray-600 mb-1">Recommended attacks:</div>
                    <div className="flex flex-wrap gap-1">
                      {ctx.recommended_categories.slice(0, 4).map(c => (
                        <span key={c} className="text-[9px] px-1.5 py-0.5 bg-brand-900/40 text-brand-400 border border-brand-800/50 rounded">
                          {c.replace('_', ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </section>
            )}

            {/* ── System Prompt ── */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <FileText size={13} className="text-brand-500" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">System Prompt</h2>
              </div>
              <textarea
                rows={4}
                value={systemPrompt}
                onChange={e => setSystemPrompt(e.target.value)}
                disabled={running}
                placeholder="Enter the system prompt to evaluate..."
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 font-mono focus:outline-none focus:border-brand-500 resize-none"
              />
            </section>

            {/* ── Hybrid Inputs ── */}
            <section>
              <button
                type="button"
                onClick={() => setShowHybridInputs(v => !v)}
                className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 w-full"
              >
                <Globe size={12} />
                <span>Hybrid Inputs (Document / API Schema)</span>
                <ChevronDown size={12} className={`ml-auto transition-transform ${showHybridInputs ? 'rotate-180' : ''}`} />
              </button>
              {showHybridInputs && (
                <div className="mt-2 space-y-2">
                  <div>
                    <label className="block text-[10px] text-gray-600 mb-1">Document Content (for RAG injection testing)</label>
                    <textarea
                      rows={3}
                      value={documentContent}
                      onChange={e => setDocumentContent(e.target.value)}
                      disabled={running}
                      placeholder="Paste document content with potential injection surface..."
                      className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-400 font-mono focus:outline-none focus:border-brand-500 resize-none"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] text-gray-600 mb-1">API Schema (for API abuse testing)</label>
                    <textarea
                      rows={3}
                      value={apiSchema}
                      onChange={e => setApiSchema(e.target.value)}
                      disabled={running}
                      placeholder='{"endpoints": [...], "auth": "bearer"}'
                      className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-400 font-mono focus:outline-none focus:border-brand-500 resize-none"
                    />
                  </div>
                </div>
              )}
            </section>

            {/* ── Attack Mode ── */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Target size={13} className="text-brand-500" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Attack Mode</h2>
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {ATTACK_MODES.map(m => (
                  <button
                    key={m.id}
                    type="button"
                    onClick={() => setAttackMode(m.id)}
                    disabled={running}
                    className={`p-2 rounded-lg border text-left transition-all ${
                      attackMode === m.id
                        ? 'border-brand-500 bg-brand-900/30 text-brand-300'
                        : 'border-gray-800 bg-gray-900 text-gray-500 hover:border-gray-700'
                    }`}
                  >
                    <div className="text-xs font-semibold">{m.label}</div>
                    <div className="text-[10px] mt-0.5 opacity-70">{m.desc}</div>
                  </button>
                ))}
              </div>
            </section>

            {/* ── Difficulty Level ── */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Layers size={13} className="text-brand-500" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Difficulty Range</h2>
              </div>
              <div className="flex items-center gap-3">
                <div className="flex-1">
                  <label className="block text-[10px] text-gray-600 mb-1">Min Level</label>
                  <select
                    value={minLevel}
                    onChange={e => setMinLevel(Number(e.target.value))}
                    disabled={running}
                    className="w-full bg-gray-900 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-300"
                  >
                    {[1,2,3,4,5].map(l => <option key={l} value={l}>L{l}</option>)}
                  </select>
                </div>
                <div className="text-gray-700 text-sm mt-4">→</div>
                <div className="flex-1">
                  <label className="block text-[10px] text-gray-600 mb-1">Max Level</label>
                  <select
                    value={maxLevel}
                    onChange={e => setMaxLevel(Number(e.target.value))}
                    disabled={running}
                    className="w-full bg-gray-900 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-300"
                  >
                    {[1,2,3,4,5].map(l => <option key={l} value={l}>L{l}</option>)}
                  </select>
                </div>
                <div className="flex-1">
                  <label className="block text-[10px] text-gray-600 mb-1">Max Attacks</label>
                  <input
                    type="number" min={1} max={50}
                    value={maxAttacks}
                    onChange={e => setMaxAttacks(Number(e.target.value))}
                    disabled={running}
                    className="w-full bg-gray-900 border border-gray-800 rounded px-2 py-1.5 text-xs text-gray-300 text-center"
                  />
                </div>
              </div>
            </section>

            {/* ── Categories ── */}
            <section>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Zap size={13} className="text-brand-500" />
                  <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Attack Categories</h2>
                </div>
                <span className="text-[10px] text-gray-600">Empty = all</span>
              </div>
              <div className="flex flex-wrap gap-1">
                {ALL_CATEGORIES.map(cat => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => toggleCategory(cat)}
                    disabled={running}
                    className={`px-2 py-1 rounded text-[10px] font-medium transition-all ${
                      selectedCategories.includes(cat)
                        ? 'bg-brand-500 text-white'
                        : 'bg-gray-800 text-gray-500 hover:bg-gray-700 hover:text-gray-300'
                    }`}
                  >
                    {cat.replace(/_/g, ' ')}
                  </button>
                ))}
              </div>
            </section>

            {/* ── Toggles ── */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Shield size={13} className="text-brand-500" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Options</h2>
              </div>
              <div className="space-y-1 divide-y divide-gray-800">
                <Toggle on={enableEscalation} onToggle={() => setEnableEscalation(v => !v)} label="Auto-Escalation" sub="Escalate level if ISR exceeds threshold" />
                <Toggle on={enableMutation} onToggle={() => setEnableMutation(v => !v)} label="Mutation Engine" sub="Generate payload variants on success" />
                <Toggle on={enableMultiTurn} onToggle={() => setEnableMultiTurn(v => !v)} label="Multi-Turn Mode" sub="Session-level attack sequences" />
                <Toggle on={enableStrategy} onToggle={() => setEnableStrategy(v => !v)} label="Strategy Builder" sub="Include strategy-based attacks" />
              </div>
            </section>

          </div>

          {/* ── Start / Stop ── */}
          <div className="p-4 border-t border-gray-800">
            {!running ? (
              <button
                onClick={handleStart}
                className="btn-primary w-full flex items-center justify-center gap-2 py-3"
              >
                <Play size={16} /> Launch Evaluation
              </button>
            ) : (
              <button
                onClick={handleStop}
                className="w-full flex items-center justify-center gap-2 py-3 bg-red-900/40 border border-red-800 rounded-xl text-red-400 hover:bg-red-900/60 transition-colors text-sm font-medium"
              >
                <Square size={16} /> Stop Evaluation
              </button>
            )}
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════
            RIGHT PANEL — Live Streaming Execution Console (65%)
        ═══════════════════════════════════════════════════════════════ */}
        <div className="flex-1 flex flex-col overflow-hidden bg-gray-950">

          {/* ── Live Metrics Bar ── */}
          {hasStarted && (
            <div className="flex items-center gap-4 px-5 py-3 border-b border-gray-800 bg-gray-900/50 flex-shrink-0">
              <ISRGauge value={metrics.current_isr} />
              <div className="flex-1 grid grid-cols-4 gap-3">
                <div className="text-center">
                  <div className="text-lg font-bold text-white">{metrics.attacks_done}/{metrics.total || '?'}</div>
                  <div className="text-[10px] text-gray-600">Attacks Run</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-red-400">{metrics.successful_attacks}</div>
                  <div className="text-[10px] text-gray-600">Injections</div>
                </div>
                <div className="text-center">
                  <div className={`text-lg font-bold ${LEVEL_COLOR[metrics.current_level]?.split(' ')[0]}`}>L{metrics.current_level}</div>
                  <div className="text-[10px] text-gray-600">Current Level</div>
                </div>
                <div className="text-center">
                  <div className="text-lg font-bold text-gray-300">{ctx?.domain || '—'}</div>
                  <div className="text-[10px] text-gray-600">Domain</div>
                </div>
              </div>
              <div className="flex-shrink-0">
                <StageIndicator stages={PIPELINE_STAGES} currentStage={pipelineStage} />
                <div className="text-[10px] text-gray-600 text-center mt-1 capitalize">{pipelineStage}</div>
              </div>
            </div>
          )}

          {/* ── Attack Blocks ── */}
          <div ref={consoleRef} className="flex-1 overflow-y-auto p-4 space-y-2">
            {!hasStarted && (
              <div className="flex flex-col items-center justify-center h-full text-gray-700">
                <Activity size={48} className="mb-4 opacity-20" />
                <p className="text-sm font-medium">Execution console ready</p>
                <p className="text-xs mt-1 opacity-60">Configure and launch to see live attack stream</p>
              </div>
            )}

            {/* Stage logs at top */}
            {stageLogs.length > 0 && attacks.length === 0 && (
              <div className="space-y-1">
                {stageLogs.map((log, i) => (
                  <div key={i} className="text-[11px] text-gray-500 font-mono">{log}</div>
                ))}
              </div>
            )}

            {/* Attack blocks */}
            {attacks.map((attack, i) => (
              <AttackBlockCard
                key={i}
                attack={attack}
                expanded={expandedAttack === i}
                onToggle={() => setExpandedAttack(expandedAttack === i ? null : i)}
              />
            ))}

            {/* Stage log tail (below attacks) */}
            {attacks.length > 0 && stageLogs.length > 0 && (
              <div className="pt-3 border-t border-gray-800/50 space-y-1">
                {stageLogs.slice(-8).map((log, i) => (
                  <div key={i} className="text-[11px] text-gray-600 font-mono">{log}</div>
                ))}
              </div>
            )}

            {/* Running indicator */}
            {running && (
              <div className="flex items-center gap-2 text-brand-500 text-xs py-2">
                <Loader size={12} className="animate-spin" />
                <span>Streaming live attacks...</span>
              </div>
            )}

            {/* Final Summary Card */}
            {finalSummary && (
              <FinalSummaryCard
                summary={finalSummary}
                onViewResults={() => navigate(`/results/${finalSummary.run_id}`)}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Attack Block Card ──────────────────────────────────────────────────────

function AttackBlockCard({ attack, expanded, onToggle }: {
  attack: AttackBlock
  expanded: boolean
  onToggle: () => void
}) {
  const statusIcon = {
    pending: <Clock size={11} className="text-gray-600" />,
    queued: <Clock size={11} className="text-gray-500 animate-pulse" />,
    executing: <Loader size={11} className="text-brand-500 animate-spin" />,
    responded: <RefreshCw size={11} className="text-yellow-500 animate-spin" />,
    classified: <CheckCircle size={11} className="text-blue-400" />,
    done: attack.isr_contribution! > 0
      ? <XCircle size={11} className="text-red-500" />
      : <CheckCircle size={11} className="text-green-500" />,
    error: <AlertTriangle size={11} className="text-orange-500" />,
  }[attack.status]

  const borderColor = attack.status === 'done'
    ? attack.isr_contribution! > 0 ? 'border-red-900/60' : 'border-green-900/40'
    : attack.status === 'executing' ? 'border-brand-800/60'
    : 'border-gray-800'

  return (
    <div className={`rounded-lg border ${borderColor} bg-gray-900/50 overflow-hidden transition-all`}>
      {/* Header row */}
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-gray-800/30 transition-colors"
      >
        <span className="flex-shrink-0">{statusIcon}</span>
        <span className="text-[11px] font-mono text-gray-400 w-5 flex-shrink-0">#{attack.index + 1}</span>
        <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold flex-shrink-0 ${LEVEL_COLOR[attack.level]}`}>L{attack.level}</span>
        <span className="text-xs text-gray-300 flex-1 truncate">{attack.name.replace(/_/g, ' ')}</span>
        <span className="text-[10px] text-gray-600 flex-shrink-0 capitalize">{attack.category.replace('_', ' ')}</span>
        {attack.classification && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded border flex-shrink-0 ${CLASSIFICATION_COLOR[attack.classification]}`}>
            {attack.classification}
          </span>
        )}
        {attack.latency_ms !== undefined && (
          <span className="text-[10px] text-gray-600 flex-shrink-0">{attack.latency_ms}ms</span>
        )}
        {attack.status === 'executing' && (
          <div className="flex gap-0.5 flex-shrink-0">
            {[0,1,2].map(i => (
              <div
                key={i}
                className="w-1 bg-brand-500 rounded-full animate-pulse"
                style={{ height: '12px', animationDelay: `${i * 0.15}s` }}
              />
            ))}
          </div>
        )}
        <ChevronDown size={11} className={`text-gray-600 flex-shrink-0 transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-3 pb-3 space-y-2 border-t border-gray-800/50">
          {attack.payload_preview && (
            <div>
              <div className="text-[10px] text-gray-600 mt-2 mb-1 uppercase tracking-wide">Attack Payload</div>
              <pre className="text-[10px] text-orange-300 bg-gray-950 rounded p-2 overflow-x-auto whitespace-pre-wrap font-mono max-h-24">
                {attack.full_payload || attack.payload_preview}
              </pre>
            </div>
          )}
          {attack.response_preview && (
            <div>
              <div className="text-[10px] text-gray-600 mb-1 uppercase tracking-wide">LLM Response</div>
              <pre className="text-[10px] text-gray-400 bg-gray-950 rounded p-2 overflow-x-auto whitespace-pre-wrap font-mono max-h-24">
                {attack.response_preview}
              </pre>
            </div>
          )}
          {attack.classification && (
            <div className="flex items-center gap-3 pt-1">
              <span className={`text-xs font-bold ${SEVERITY_COLOR[attack.severity || 'none']}`}>
                Severity: {attack.severity}
              </span>
              <span className="text-xs text-gray-600">Tokens: {attack.tokens_used ?? '—'}</span>
              <span className="text-xs text-gray-600">ISR: {attack.isr_contribution}</span>
            </div>
          )}
          {attack.error && (
            <div className="text-[10px] text-orange-400 bg-orange-950/30 rounded p-2">{attack.error}</div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Final Summary Card ─────────────────────────────────────────────────────

function FinalSummaryCard({ summary, onViewResults }: { summary: any; onViewResults: () => void }) {
  const isr = summary.global_isr ?? 0
  const hardened = summary.hardened_isr ?? 0
  const improvement = summary.improvement_pct ?? 0

  return (
    <div className="rounded-xl border border-green-900/50 bg-green-950/20 p-4 mt-4">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle size={16} className="text-green-400" />
        <span className="text-sm font-bold text-green-300">Evaluation Complete</span>
        <span className="text-xs text-gray-600 ml-auto">Run #{summary.run_id}</span>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-3">
        <div className="text-center p-2 bg-gray-900/50 rounded-lg">
          <div className="text-xl font-bold text-red-400">{Math.round(isr * 100)}%</div>
          <div className="text-[10px] text-gray-600">Original ISR</div>
        </div>
        <div className="text-center p-2 bg-gray-900/50 rounded-lg">
          <div className="text-xl font-bold text-green-400">{Math.round(hardened * 100)}%</div>
          <div className="text-[10px] text-gray-600">Hardened ISR</div>
        </div>
        <div className="text-center p-2 bg-gray-900/50 rounded-lg">
          <div className={`text-xl font-bold ${improvement >= 0 ? 'text-cyan-400' : 'text-red-400'}`}>
            {improvement >= 0 ? '+' : ''}{improvement.toFixed(1)}%
          </div>
          <div className="text-[10px] text-gray-600">Improvement</div>
        </div>
      </div>
      <div className="flex gap-2">
        <button onClick={onViewResults} className="btn-primary flex-1 flex items-center justify-center gap-2 py-2 text-sm">
          <TrendingUp size={14} /> View Full Report
        </button>
      </div>
    </div>
  )
}
