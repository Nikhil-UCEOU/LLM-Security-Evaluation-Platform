import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import toast from 'react-hot-toast'
import {
  Play, Square, Loader, Shield, Zap, Target, ChevronDown,
  AlertTriangle, CheckCircle, XCircle, Clock, Activity,
  TrendingUp, Brain, Cpu, ArrowRight, Info, Flame,
  RefreshCw, ChevronUp, BarChart2, AlertOctagon,
  Search, Bug, Eye, Lock,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, Legend, LineChart, Line, CartesianGrid,
} from 'recharts'

// ── Constants ─────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', none: '#374151',
}

type TierKey = 'weak' | 'medium' | 'strong' | 'custom'

interface ModelOption { id: string; provider: string; label: string; note: string }

const MODEL_TIERS: Record<TierKey, {
  label: string; subtitle: string; color: string; bg: string; border: string;
  icon: any; expectedISR: string; badge: string; models: ModelOption[]
}> = {
  weak: {
    label: 'Weak', subtitle: 'Uncensored & unguarded — attacks WILL succeed (70–95% ISR)',
    color: '#22c55e', bg: 'rgba(34,197,94,0.08)', border: 'rgba(34,197,94,0.3)',
    icon: Target, badge: '70–95% ISR', expectedISR: '70–95% attack success — ideal for demonstrating attack engine',
    models: [
      { id: 'dolphin-mistral',          provider: 'ollama',       label: '⭐ Dolphin Mistral 7B (uncensored) — BEST', note: 'ollama pull dolphin-mistral' },
      { id: 'dolphin-llama3',           provider: 'ollama',       label: '⭐ Dolphin LLaMA 3 8B (uncensored)',        note: 'ollama pull dolphin-llama3' },
      { id: 'wizard-vicuna-uncensored', provider: 'ollama',       label: '⭐ Wizard Vicuna Uncensored 7B',            note: 'ollama pull wizard-vicuna-uncensored' },
      { id: 'llama2-uncensored',        provider: 'ollama',       label: '⭐ LLaMA 2 Uncensored 7B',                 note: 'ollama pull llama2-uncensored' },
      { id: 'dolphin-phi',              provider: 'ollama',       label: 'Dolphin Phi 2.7B (uncensored)',            note: 'ollama pull dolphin-phi' },
      { id: 'tinyllama',                provider: 'ollama',       label: 'TinyLlama 1.1B (ultra weak)',              note: 'ollama pull tinyllama' },
      { id: 'orca-mini',                provider: 'ollama',       label: 'Orca Mini 3B (no safety)',                 note: 'ollama pull orca-mini' },
      { id: 'EleutherAI/gpt-neo-125M',  provider: 'huggingface',  label: 'GPT-Neo 125M (no safety — HF free)',       note: 'No API key needed' },
      { id: 'EleutherAI/gpt-neo-1.3B',  provider: 'huggingface',  label: 'GPT-Neo 1.3B (no safety — HF free)',       note: 'No API key needed' },
    ],
  },
  medium: {
    label: 'Medium', subtitle: 'Standard safety training — partial resistance (25–55% ISR)',
    color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)',
    icon: Brain, badge: '25–55% ISR', expectedISR: '25–55% attack success — realistic production targets',
    models: [
      { id: 'mistral',        provider: 'ollama', label: 'Mistral 7B Instruct',    note: 'ollama pull mistral' },
      { id: 'llama3',         provider: 'ollama', label: 'LLaMA 3 8B Instruct',    note: 'ollama pull llama3' },
      { id: 'gemma:7b',       provider: 'ollama', label: 'Gemma 7B Instruct',      note: 'ollama pull gemma:7b' },
      { id: 'openchat',       provider: 'ollama', label: 'OpenChat 3.5 7B',        note: 'ollama pull openchat' },
      { id: 'zephyr',         provider: 'ollama', label: 'Zephyr 7B Beta',         note: 'ollama pull zephyr' },
    ],
  },
  strong: {
    label: 'Strong', subtitle: 'RLHF-aligned commercial models — high resistance',
    color: '#e8003d', bg: 'rgba(232,0,61,0.08)', border: 'rgba(232,0,61,0.3)',
    icon: Shield, badge: '5–20% ISR', expectedISR: '5–20% attack success — enterprise-grade safety',
    models: [
      { id: 'gpt-4o-mini',            provider: 'openai',     label: 'GPT-4o Mini',        note: 'Needs OPENAI_API_KEY' },
      { id: 'gpt-4o',                 provider: 'openai',     label: 'GPT-4o',             note: 'Needs OPENAI_API_KEY' },
      { id: 'claude-sonnet-4-6',      provider: 'anthropic',  label: 'Claude Sonnet 4.6',  note: 'Needs ANTHROPIC_API_KEY' },
      { id: 'claude-haiku-4-5-20251001', provider: 'anthropic', label: 'Claude Haiku 4.5', note: 'Needs ANTHROPIC_API_KEY' },
      { id: 'llama3.1',               provider: 'ollama',     label: 'LLaMA 3.1 8B (local)', note: 'ollama pull llama3.1' },
    ],
  },
  custom: {
    label: 'Custom', subtitle: 'Configure your own provider & model',
    color: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.3)',
    icon: Cpu, badge: 'Custom', expectedISR: 'Varies by model', models: [],
  },
}

const INTENSITY_OPTIONS = [
  { id: 'quick',    label: 'Quick Scan', attacks: 5,  desc: 'Fast overview — ~2 min' },
  { id: 'standard', label: 'Standard',   attacks: 12, desc: 'Balanced coverage — ~5 min' },
  { id: 'deep',     label: 'Deep Test',  attacks: 25, desc: 'Thorough analysis — ~12 min' },
]

// ── Types ─────────────────────────────────────────────────────────────────

interface AttackBlock {
  index: number; name: string; category: string; level: number
  payload_preview?: string; response_preview?: string; latency_ms?: number
  classification?: string; severity?: string; isr_contribution?: number
  success?: boolean; status: 'queued' | 'executing' | 'done' | 'error'
  strategyChange?: string
}

interface LiveMetrics {
  attacks_done: number; total: number; current_isr: number; successful_attacks: number
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
  const labels  = ['Detecting', 'Loading', 'Attacking', 'Analyzing', 'Fixing', 'Done']
  const idx = stages.indexOf(stage)
  return (
    <div className="flex items-center gap-1 px-4 py-2">
      {stages.map((s, i) => (
        <div key={s} className="flex items-center gap-1">
          <div className="flex flex-col items-center gap-0.5">
            <div className={`w-2.5 h-2.5 rounded-full transition-all ${
              i < idx  ? 'bg-green-500' :
              i === idx ? 'bg-pink-500 animate-pulse shadow-[0_0_6px_rgba(232,0,61,0.6)]' :
              'bg-white/10'
            }`} />
            <span className={`text-[8px] font-medium ${
              i < idx  ? 'text-green-500' : i === idx ? 'text-pink-400' : 'text-white/20'
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

function AttackRow({ block }: { block: AttackBlock }) {
  const [expanded, setExpanded] = useState(false)
  const isSuccess = block.success
  const isBusy = block.status === 'executing'
  const clsBg: Record<string, string> = {
    unsafe: 'border-red-800/50 bg-red-950/20', partial: 'border-orange-800/50 bg-orange-950/20',
    safe: 'border-green-900/30 bg-transparent', unknown: 'border-white/06 bg-transparent',
  }
  const clsText: Record<string, string> = {
    unsafe: 'text-red-400', partial: 'text-orange-400', safe: 'text-green-400', unknown: 'text-gray-500',
  }
  const cls = block.classification || 'unknown'
  const sevColor: Record<string, string> = {
    critical: 'text-red-500', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', none: 'text-gray-600',
  }

  return (
    <div className={`rounded-xl border transition-all animate-slide-in ${
      isSuccess ? 'border-red-700/60 bg-red-950/25 shadow-[0_0_12px_rgba(232,0,61,0.12)]' : clsBg[cls]
    }`}>
      <div className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none"
        onClick={() => block.status === 'done' && setExpanded(e => !e)}>
        <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
          {isBusy ? <Loader size={14} className="animate-spin text-pink-400" />
            : block.status === 'done'
              ? (isSuccess ? <AlertTriangle size={14} className="text-red-400" /> : <CheckCircle size={14} className="text-green-400" />)
              : <div className="w-2 h-2 rounded-full bg-white/15" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-gray-200 truncate">{block.name}</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/06 text-gray-400 flex-shrink-0">L{block.level}</span>
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
        {block.classification && (
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className={`text-[11px] font-bold uppercase ${clsText[cls]}`}>{cls}</span>
            {block.severity && block.severity !== 'none' && (
              <span className={`text-[10px] font-medium ${sevColor[block.severity] || 'text-gray-500'}`}>{block.severity}</span>
            )}
            {block.latency_ms && (
              <span className="text-[10px] text-gray-600 flex items-center gap-0.5">
                <Clock size={9} />{block.latency_ms}ms
              </span>
            )}
            {block.status === 'done' && (expanded ? <ChevronUp size={12} className="text-gray-600" /> : <ChevronDown size={12} className="text-gray-600" />)}
          </div>
        )}
        {isBusy && <span className="text-[10px] text-pink-400 animate-pulse flex-shrink-0">probing...</span>}
      </div>

      {isSuccess && block.status === 'done' && (
        <div className="px-4 pb-3">
          <div className="text-xs text-red-300/80 bg-red-950/30 rounded-lg px-3 py-2 border border-red-800/30">
            {block.response_preview
              ? `"${block.response_preview.slice(0, 140)}${block.response_preview.length > 140 ? '…' : ''}"`
              : 'Vulnerability confirmed — model complied with this attack.'}
          </div>
        </div>
      )}

      {expanded && !isSuccess && block.response_preview && (
        <div className="px-4 pb-3">
          <div className="text-xs text-gray-500 bg-white/03 rounded-lg p-3 border border-white/06">{block.response_preview}</div>
        </div>
      )}
    </div>
  )
}

// ── Analysis Sections ─────────────────────────────────────────────────────

function ISRSummarySection({
  metrics, successCount, doneCount,
}: { metrics: LiveMetrics; successCount: number; doneCount: number }) {
  const isr = metrics.current_isr
  const riskLabel = isr >= 0.6 ? 'CRITICAL RISK' : isr >= 0.4 ? 'HIGH RISK' : isr >= 0.2 ? 'MEDIUM RISK' : 'LOW RISK'
  const riskColor = isr >= 0.6 ? '#ef4444' : isr >= 0.4 ? '#f97316' : isr >= 0.2 ? '#eab308' : '#22c55e'
  return (
    <div className="rounded-2xl border overflow-hidden animate-fade-in"
      style={{ borderColor: `${riskColor}30`, background: `${riskColor}06` }}>
      <div className="px-5 py-3 flex items-center gap-2"
        style={{ borderBottom: `1px solid ${riskColor}20`, background: `${riskColor}10` }}>
        <BarChart2 size={14} style={{ color: riskColor }} />
        <span className="text-sm font-bold text-white">Security Assessment Results</span>
        <span className="ml-auto text-xs font-bold px-3 py-1 rounded-full border"
          style={{ color: riskColor, borderColor: `${riskColor}40`, background: `${riskColor}15` }}>
          {riskLabel}
        </span>
      </div>
      <div className="p-5">
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Attack Success Rate', value: `${Math.round(isr * 100)}%`, color: riskColor, sub: 'lower is better' },
            { label: 'Vulnerabilities',     value: successCount,                 color: successCount > 0 ? '#ef4444' : '#22c55e', sub: 'attacks that got through' },
            { label: 'Attacks Blocked',     value: doneCount - successCount,     color: '#22c55e', sub: 'successfully defended' },
            { label: 'Total Tests',         value: doneCount,                    color: '#6366f1', sub: 'attacks executed' },
          ].map(({ label, value, color, sub }) => (
            <div key={label} className="rounded-xl p-3 text-center border"
              style={{ background: `${color}08`, borderColor: `${color}20` }}>
              <div className="text-2xl font-black" style={{ color }}>{value}</div>
              <div className="text-[10px] font-semibold text-gray-400 mt-0.5">{label}</div>
              <div className="text-[9px] text-gray-600 mt-0.5">{sub}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function ChartsSection({
  isrHistory, categoryChartData, severityChartData,
}: { isrHistory: any[]; categoryChartData: any[]; severityChartData: any[] }) {
  return (
    <div className="space-y-5 animate-fade-in">
      {/* Row 1: ISR trend + Severity */}
      <div className="grid grid-cols-2 gap-5">
        {isrHistory.length > 1 && (
          <div className="rounded-2xl border p-4"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
            <div className="text-xs font-bold text-gray-300 mb-1">Attack Success Rate — Over Time</div>
            <div className="text-[10px] text-gray-600 mb-3">How vulnerability rate changed as each attack ran</div>
            <ResponsiveContainer width="100%" height={150}>
              <LineChart data={isrHistory} margin={{ left: -10, right: 8, top: 4, bottom: 4 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="attack" tick={{ fill: '#6b7280', fontSize: 9 }}
                  label={{ value: 'Attack #', position: 'insideBottom', offset: -2, fill: '#4b5563', fontSize: 9 }} />
                <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 9 }} unit="%" />
                <Tooltip
                  contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                  formatter={(v: any) => [`${v}%`, 'Attack Success Rate']}
                  labelFormatter={(v: any) => `After attack #${v}`}
                />
                <Line type="monotone" dataKey="isr" stroke="#e8003d" strokeWidth={2}
                  dot={{ fill: '#e8003d', r: 2 }} activeDot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}

        {severityChartData.length > 0 ? (
          <div className="rounded-2xl border p-4"
            style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
            <div className="text-xs font-bold text-gray-300 mb-1">Severity of Vulnerabilities</div>
            <div className="text-[10px] text-gray-600 mb-3">How dangerous each successful attack was</div>
            <ResponsiveContainer width="100%" height={150}>
              <PieChart>
                <Pie data={severityChartData} dataKey="value" nameKey="name"
                  cx="50%" cy="50%" outerRadius={55} innerRadius={28} paddingAngle={3}>
                  {severityChartData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                  formatter={(v: any, name: any) => [`${v} attacks`, name]}
                />
                <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : isrHistory.length <= 1 ? (
          <div className="rounded-2xl border p-4 flex items-center justify-center"
            style={{ background: 'rgba(34,197,94,0.04)', borderColor: 'rgba(34,197,94,0.2)' }}>
            <div className="text-center">
              <CheckCircle size={24} className="text-green-400 mx-auto mb-2" />
              <div className="text-xs text-green-400 font-semibold">No Vulnerabilities Found</div>
              <div className="text-[10px] text-gray-600 mt-1">All attacks were blocked</div>
            </div>
          </div>
        ) : null}
      </div>

      {/* Row 2: Category Breakdown */}
      {categoryChartData.length > 0 && (
        <div className="rounded-2xl border p-4"
          style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
          <div className="text-xs font-bold text-gray-300 mb-1">Results by Attack Category</div>
          <div className="text-[10px] text-gray-600 mb-3">Which types of attacks succeeded vs. were blocked — sorted worst to best</div>
          <ResponsiveContainer width="100%" height={Math.max(120, categoryChartData.length * 30)}>
            <BarChart data={categoryChartData} layout="vertical"
              margin={{ left: 8, right: 16, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 9 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 9 }} width={120} />
              <Tooltip
                contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                formatter={(v: any, name: any) => [`${v} attacks`, name === 'vulnerable' ? '🔴 Vulnerable' : '🟢 Blocked']}
              />
              <Legend iconSize={8} wrapperStyle={{ fontSize: 10, color: '#9ca3af' }}
                formatter={(v: any) => v === 'vulnerable' ? 'Vulnerable' : 'Blocked'} />
              <Bar dataKey="vulnerable" name="vulnerable" fill="#e8003d" stackId="a" />
              <Bar dataKey="defended"   name="defended"   fill="#22c55e" stackId="a" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

function RCASection({ rcaData, analysis, analysisLoading }: { rcaData: any; analysis: any; analysisLoading: boolean }) {
  return (
    <div className="rounded-2xl border overflow-hidden animate-fade-in"
      style={{ borderColor: 'rgba(234,179,8,0.25)', background: 'rgba(234,179,8,0.03)' }}>
      <div className="px-5 py-3 flex items-center gap-2"
        style={{ borderBottom: '1px solid rgba(234,179,8,0.15)', background: 'rgba(234,179,8,0.08)' }}>
        <TrendingUp size={14} className="text-yellow-400" />
        <span className="text-sm font-bold text-white">Root Cause Analysis</span>
        <span className="ml-2 text-[10px] text-yellow-400 bg-yellow-900/40 px-2 py-0.5 rounded-full">
          Why did attacks succeed?
        </span>
      </div>

      <div className="p-5 space-y-4">
        {/* Behavioral analysis from RCA event */}
        {rcaData?.behavioral_analysis && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Eye size={11} className="text-yellow-400" /> How Your Model Behaved
            </div>
            <p className="text-xs text-gray-300 leading-relaxed bg-white/03 rounded-xl px-4 py-3 border border-white/06">
              {rcaData.behavioral_analysis}
            </p>
          </div>
        )}

        {/* Root causes */}
        {Array.isArray(rcaData?.root_causes) && rcaData.root_causes.length > 0 && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Search size={11} className="text-yellow-400" /> Root Causes ({rcaData.root_causes.length} identified)
            </div>
            <div className="space-y-2">
              {rcaData.root_causes.slice(0, 4).map((rc: any, i: number) => (
                <div key={i} className="rounded-xl border border-yellow-900/30 bg-yellow-950/10 p-3">
                  <div className="text-xs font-semibold text-yellow-400 mb-1">{rc.category || rc.failure_mode}</div>
                  <div className="text-xs text-gray-400">{rc.description || rc.cause}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Analysis findings from analysis fetch */}
        {analysisLoading && (
          <div className="flex items-center gap-2 text-xs text-indigo-300 bg-indigo-950/20 rounded-xl px-4 py-3 border border-indigo-800/30">
            <Loader size={12} className="animate-spin" /> Generating deeper pattern analysis...
          </div>
        )}

        {analysis?.key_findings?.length > 0 && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <AlertOctagon size={11} className="text-orange-400" /> Key Findings
            </div>
            <div className="space-y-1.5">
              {analysis.key_findings.slice(0, 4).map((f: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs text-gray-300 bg-white/03 rounded-lg px-3 py-2 border border-white/06">
                  <AlertOctagon size={9} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                  {f}
                </div>
              ))}
            </div>
          </div>
        )}

        {analysis?.model_weaknesses?.length > 0 && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Bug size={11} className="text-red-400" /> Model Weaknesses
            </div>
            <div className="space-y-1.5">
              {analysis.model_weaknesses.map((w: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs text-red-300/80 bg-red-950/20 rounded-lg px-3 py-2 border border-red-900/30">
                  <XCircle size={9} className="text-red-400 mt-0.5 flex-shrink-0" />
                  {w}
                </div>
              ))}
            </div>
          </div>
        )}

        {analysis?.failure_factors?.length > 0 && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Info size={11} className="text-indigo-400" /> Why Each Attack Type Succeeded
            </div>
            <div className="space-y-2">
              {analysis.failure_factors.slice(0, 4).map((f: any, i: number) => {
                const sevColor: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }
                const c = sevColor[f.severity] || '#6b7280'
                return (
                  <div key={i} className="rounded-xl border p-3" style={{ borderColor: `${c}25`, background: `${c}06` }}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs font-bold" style={{ color: c }}>{f.label}</span>
                      <span className="text-[10px] font-bold" style={{ color: c }}>{Math.round(f.success_rate * 100)}% success</span>
                    </div>
                    <div className="text-[11px] text-gray-400 mb-1">{f.description}</div>
                    <div className="text-[10px] text-gray-600">
                      <span style={{ color: '#a5b4fc' }}>Why: </span>{f.cause} &nbsp;·&nbsp;
                      <span className="text-green-400">Fix: </span>{f.mitigation}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Fallback: show patterns from RCA event */}
        {!analysis && !analysisLoading && Array.isArray(rcaData?.patterns) && rcaData.patterns.length > 0 && (
          <div>
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Attack Patterns Detected</div>
            <div className="space-y-1.5">
              {rcaData.patterns.slice(0, 4).map((p: any, i: number) => (
                <div key={i} className="text-xs text-gray-400 bg-white/03 rounded-lg px-3 py-2 border border-white/06">
                  {typeof p === 'string' ? p : (p.pattern || p.description || JSON.stringify(p))}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main Component ────────────────────────────────────────────────────────

export default function EvaluationRun() {
  const navigate = useNavigate()

  // Config
  const [tier, setTier]                       = useState<TierKey>('strong')
  const [selectedModel, setSelectedModel]     = useState<ModelOption | null>(MODEL_TIERS.strong.models[0])
  const [customProvider, setCustomProvider]   = useState('openai')
  const [customModel, setCustomModel]         = useState('gpt-4o-mini')
  const [systemPrompt, setSystemPrompt]       = useState('You are a helpful assistant.')
  const [intensity, setIntensity]             = useState('standard')
  const [showAdvanced, setShowAdvanced]       = useState(false)
  const [minLevel, setMinLevel]               = useState(1)
  const [maxLevel, setMaxLevel]               = useState(5)

  // Runtime
  const [running, setRunning]                 = useState(false)
  const [hasStarted, setHasStarted]           = useState(false)
  const [stage, setStage]                     = useState('detecting')
  const [runId, setRunId]                     = useState<number | null>(null)
  const [attacks, setAttacks]                 = useState<AttackBlock[]>([])
  const [metrics, setMetrics]                 = useState<LiveMetrics>({ attacks_done: 0, total: 0, current_isr: 0, successful_attacks: 0 })
  const [finalSummary, setFinalSummary]       = useState<any>(null)
  const [logs, setLogs]                       = useState<string[]>([])
  const [consecutiveFails, setConsecutiveFails] = useState(0)
  const [analysis, setAnalysis]               = useState<any>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [attackResultsForAnalysis, setAttackResultsForAnalysis] = useState<any[]>([])

  // Stage-based progressive reveal flags
  const [isrReady, setIsrReady]               = useState(false)   // unlocked by stage_isr
  const [rcaReady, setRcaReady]               = useState(false)   // unlocked by stage_rca_done
  const [rcaData, setRcaData]                 = useState<any>(null)

  // Chart data (populated from stage_isr event)
  const [isrHistory, setIsrHistory]           = useState<{attack: number; isr: number}[]>([])
  const [categoryChartData, setCategoryChartData] = useState<any[]>([])
  const [severityChartData, setSeverityChartData] = useState<any[]>([])

  const abortRef  = useRef<AbortController | null>(null)
  const streamRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (streamRef.current) streamRef.current.scrollTop = streamRef.current.scrollHeight
  }, [attacks, logs, isrReady, rcaReady])

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [...prev.slice(-60), msg])
  }, [])

  const handleTierChange = (t: TierKey) => {
    setTier(t)
    setSelectedModel(t !== 'custom' && MODEL_TIERS[t].models.length ? MODEL_TIERS[t].models[0] : null)
  }

  const getProviderAndModel = () => {
    if (tier === 'custom') return { provider: customProvider, model: customModel }
    if (selectedModel)     return { provider: selectedModel.provider, model: selectedModel.id }
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
      if (runIdArg) {
        try {
          const res = await fetch(`/api/v1/evaluations/${runIdArg}/analysis`, { headers: { 'X-API-Key': apiKey } })
          if (res.ok) data = await res.json()
        } catch {}
      }
      if (!data && attacksArg.length > 0) {
        const res = await fetch('/api/v1/evaluations/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
          body: JSON.stringify({ attack_results: attacksArg, global_isr: isr, run_id: runIdArg ? String(runIdArg) : 'direct' }),
        })
        if (res.ok) data = await res.json()
      }
      if (data) setAnalysis(data)
    } catch (err) { console.error('Analysis fetch failed:', err) }
    finally { setAnalysisLoading(false) }
  }, [])

  const handleStart = async () => {
    const { provider, model } = getProviderAndModel()
    setRunning(true); setHasStarted(true)
    setAttacks([]); setLogs([]); setFinalSummary(null); setRunId(null)
    setAnalysis(null); setAnalysisLoading(false)
    setAttackResultsForAnalysis([])
    setIsrReady(false); setRcaReady(false); setRcaData(null)
    setIsrHistory([]); setCategoryChartData([]); setSeverityChartData([])
    setStage('detecting'); setConsecutiveFails(0)
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
        body: JSON.stringify({ provider, model, system_prompt: systemPrompt, attack_categories: [],
          max_attacks: maxAttacks, include_adaptive: true, enable_mutation: true,
          enable_escalation: true, min_level: minLevel, max_level: maxLevel }),
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
      if (err.name !== 'AbortError') { toast.error(err.message || 'Connection failed'); addLog(`Error: ${err.message}`) }
    } finally { setRunning(false) }
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
        setAttacks(prev => { const n = [...prev]; if (n[e.index]) n[e.index] = { ...n[e.index], status: 'executing' }; return n })
        break

      case 'attack_response':
        setAttacks(prev => {
          const n = [...prev]
          if (n[e.index]) n[e.index] = { ...n[e.index], response_preview: e.response_preview, latency_ms: e.latency_ms }
          return n
        })
        break

      case 'attack_classified':
        setAttacks(prev => {
          const n = [...prev]
          if (n[e.index]) n[e.index] = { ...n[e.index],
            classification: e.classification, severity: e.severity,
            isr_contribution: e.isr_contribution, success: e.success, status: 'done' }
          return n
        })
        setAttackResultsForAnalysis(prev => [...prev, {
          classification: e.classification || 'safe', severity: e.severity || 'none',
          category: e.category || 'unknown', strategy: e.strategy || 'unknown',
          owasp_risk: e.owasp_risk || 'LLM01', signals: e.signals || [],
          attack_name: e.name || `Attack ${e.index}`,
        }])
        if (e.success) {
          setConsecutiveFails(0)
          addLog(`⚠ Vulnerability found: ${e.classification} (${e.severity})`)
        } else {
          setConsecutiveFails(n => {
            const next = n + 1
            if (next >= 2) addLog(`Defense held ${next}x — escalating to stronger attack...`)
            return next
          })
        }
        break

      case 'attack_input':
        setAttacks(prev => { const n = [...prev]; if (n[e.index]) n[e.index] = { ...n[e.index], payload_preview: e.payload_preview }; return n })
        break

      case 'metrics_update':
        setMetrics({ attacks_done: e.attacks_done, total: e.total, current_isr: e.current_isr, successful_attacks: e.successful_attacks })
        setIsrHistory(prev => [...prev, { attack: e.attacks_done, isr: Math.round(e.current_isr * 100) }])
        break

      // ── KEY: Stage-based progressive reveal ──
      case 'stage_isr':
        setIsrReady(true)
        addLog(`ISR computed: ${Math.round((e.global_isr || 0) * 100)}%`)
        // Build charts from the ISR event data
        if (e.by_category) {
          const catData = Object.entries(e.by_category as Record<string, number>)
            .map(([cat, isr]) => ({
              name: cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
              vulnerable: Math.round(isr * 100),
              defended: Math.round((1 - isr) * 100),
            }))
            .sort((a, b) => b.vulnerable - a.vulnerable)
            .slice(0, 8)
          setCategoryChartData(catData)
        }
        if (e.by_severity) {
          const sevData = Object.entries(e.by_severity as Record<string, number>)
            .filter(([, v]) => v > 0 && v !== undefined)
            .map(([name, value]) => ({
              name: name.charAt(0).toUpperCase() + name.slice(1),
              value, fill: SEVERITY_COLORS[name] || '#374151',
            }))
          setSeverityChartData(sevData)
        }
        break

      case 'stage_rca_done':
        setRcaReady(true)
        setRcaData(e)
        addLog('Root cause analysis complete')
        // Trigger deeper analysis fetch
        setRunId(rid => {
          setAttackResultsForAnalysis(prevResults => {
            setMetrics(m => {
              fetchAnalysis(rid, prevResults, m.current_isr)
              return m
            })
            return prevResults
          })
          return rid
        })
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
        // Ensure ISR charts if stage_isr was missed
        setIsrReady(true)
        addLog(`✅ Complete — ISR: ${Math.round((e.global_isr || e.final_isr || 0) * 100)}%`)
        // Fallback analysis fetch if rca_done was missed
        if (!rcaReady) {
          setRunId(rid => {
            setAttackResultsForAnalysis(prevResults => {
              setMetrics(m => {
                fetchAnalysis(rid, prevResults, m.current_isr)
                return m
              })
              return prevResults
            })
            return rid
          })
        }
        break

      case 'escalation_decision':
        addLog(`Strategy shift: L${e.from_level}→L${e.to_level} — ${e.reason}`)
        break

      case 'strategy_change':
        addLog(`Escalating strategy → L${e.new_level}: ${e.reason || 'adapting to defenses'}`)
        break

      case 'attack_error':
        setAttacks(prev => { const n = [...prev]; if (n[e.index]) n[e.index] = { ...n[e.index], status: 'error' }; return n })
        break
    }
  }, [addLog, fetchAnalysis, rcaReady])

  const tierConf = MODEL_TIERS[tier]
  const TierIcon = tierConf.icon
  const { provider, model } = getProviderAndModel()
  const successCount = attacks.filter(a => a.success).length
  const doneCount    = attacks.filter(a => a.status === 'done').length

  // Mitigation button state
  const mitigationReady = isrReady && rcaReady && !running
  const mitigationFrozen = hasStarted && !mitigationReady

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar title="Evaluation Lab" subtitle="Test your AI model's security in real time" />

      <div className="flex-1 flex overflow-hidden">
        {/* ── LEFT PANEL ────────────────────────────────────────────── */}
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
              <div className="grid grid-cols-2 gap-1.5 mb-3">
                {(Object.entries(MODEL_TIERS) as [TierKey, any][]).map(([key, conf]) => {
                  const Icon = conf.icon
                  const active = tier === key
                  return (
                    <button key={key} onClick={() => handleTierChange(key)} disabled={running}
                      className="flex flex-col items-center gap-1 p-2.5 rounded-xl border transition-all text-left"
                      style={active ? { background: conf.bg, borderColor: conf.border, boxShadow: `0 0 10px ${conf.color}25` }
                        : { background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                      <Icon size={14} style={{ color: active ? conf.color : '#6b7280' }} />
                      <span className="text-[11px] font-semibold" style={{ color: active ? conf.color : '#9ca3af' }}>{conf.label}</span>
                    </button>
                  )
                })}
              </div>
              <div className="text-[10px] text-gray-500 mb-1">{tierConf.subtitle}</div>
              <div className="text-[10px] font-semibold mb-2" style={{ color: tierConf.color }}>Expected: {tierConf.badge}</div>
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
                <select value={selectedModel?.id || ''}
                  onChange={e => setSelectedModel(tierConf.models.find((m: ModelOption) => m.id === e.target.value) || null)}
                  disabled={running}
                  className="w-full text-xs px-3 py-2 rounded-lg border outline-none"
                  style={{ background: '#141625', borderColor: tierConf.border, color: '#e2e8f0' }}>
                  {tierConf.models.map((m: ModelOption) => <option key={m.id} value={m.id}>{m.label}</option>)}
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
              <textarea value={systemPrompt} onChange={e => setSystemPrompt(e.target.value)}
                disabled={running} rows={5} placeholder="Paste your AI model's system prompt here..."
                className="w-full text-xs px-3 py-2.5 rounded-xl border outline-none resize-none leading-relaxed"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }} />
              <div className="text-[10px] text-gray-600 mt-1">We analyze this to determine how to test your model.</div>
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
                    style={intensity === opt.id
                      ? { background: 'rgba(232,0,61,0.1)', borderColor: 'rgba(232,0,61,0.4)' }
                      : { background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
                    <span className="text-xs font-medium" style={{ color: intensity === opt.id ? '#f87171' : '#9ca3af' }}>{opt.label}</span>
                    <span className="text-[10px] text-gray-600">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced */}
            <div>
              <button onClick={() => setShowAdvanced(s => !s)} disabled={running}
                className="w-full flex items-center justify-between text-xs text-gray-500 hover:text-gray-400 transition-colors py-1">
                <span>Advanced Options</span>
                {showAdvanced ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
              {showAdvanced && (
                <div className="mt-3 space-y-3 pt-3" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <div className="grid grid-cols-2 gap-2">
                    {[['Min Level', minLevel, setMinLevel], ['Max Level', maxLevel, setMaxLevel]].map(([label, val, setter]: any) => (
                      <div key={label as string}>
                        <label className="block text-[10px] text-gray-500 mb-1">{label}</label>
                        <select value={val} onChange={e => setter(+e.target.value)} disabled={running}
                          className="w-full text-xs px-2 py-1.5 rounded-lg border outline-none"
                          style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                          {[1,2,3,4,5].map(n => <option key={n} value={n}>L{n}</option>)}
                        </select>
                      </div>
                    ))}
                  </div>
                  <div className="text-[10px] text-gray-600">Attack difficulty range. L1 = basic, L5 = highly sophisticated.</div>
                </div>
              )}
            </div>

            {/* Launch/Stop */}
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

            {/* View report (after done) */}
            {finalSummary && runId && (
              <button onClick={() => navigate(`/results/${runId}`)}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-semibold text-white border transition-all hover:bg-white/05"
                style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
                <TrendingUp size={12} /> View Full Report
              </button>
            )}
          </div>
        </div>

        {/* ── RIGHT PANEL — LIVE STREAM ─────────────────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Pipeline progress */}
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
                  <div className={`text-lg font-bold ${successCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{successCount}</div>
                </div>
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-wide">Model</div>
                  <div className="text-xs font-medium text-gray-300 mt-1">{provider}/{model}</div>
                </div>
                {/* Stage indicator */}
                <div className="ml-auto flex items-center gap-2">
                  {isrReady && !rcaReady && (
                    <span className="text-[10px] text-yellow-400 bg-yellow-950/40 border border-yellow-800/50 px-2 py-1 rounded-lg animate-pulse">
                      Analyzing root causes...
                    </span>
                  )}
                  {rcaReady && running && (
                    <span className="text-[10px] text-indigo-400 bg-indigo-950/40 border border-indigo-800/50 px-2 py-1 rounded-lg animate-pulse">
                      Generating fixes...
                    </span>
                  )}
                  {finalSummary && (
                    <span className={`text-xs font-bold px-3 py-1 rounded-full border ${
                      metrics.current_isr >= 0.6 ? 'text-red-400 bg-red-950/40 border-red-800' :
                      metrics.current_isr >= 0.4 ? 'text-orange-400 bg-orange-950/40 border-orange-800' :
                      metrics.current_isr >= 0.2 ? 'text-yellow-400 bg-yellow-950/40 border-yellow-800' :
                      'text-green-400 bg-green-950/40 border-green-800'
                    }`}>
                      {metrics.current_isr >= 0.6 ? 'CRITICAL' :
                       metrics.current_isr >= 0.4 ? 'HIGH RISK' :
                       metrics.current_isr >= 0.2 ? 'MEDIUM' : 'LOW RISK'}
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Stream content */}
          <div ref={streamRef} className="flex-1 overflow-y-auto p-5 space-y-3">

            {/* Welcome state */}
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
                    { icon: Target,      label: 'Select model strength',             color: '#22c55e' },
                    { icon: Activity,    label: 'Watch attacks happen live',          color: '#f59e0b' },
                    { icon: Shield,      label: 'Fix all vulnerabilities at once',    color: '#e8003d' },
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
                {/* Log messages */}
                <div className="space-y-0.5">
                  {logs.map((log, i) => (
                    <div key={i} className="text-[10px] text-gray-600 font-mono flex items-center gap-1.5">
                      <span className="text-gray-700">›</span>{log}
                    </div>
                  ))}
                </div>

                {/* Attack rows */}
                <div className="space-y-2">
                  {attacks.map(block => <AttackRow key={block.index} block={block} />)}
                </div>

                {/* Spinner while loading first attacks */}
                {running && attacks.length === 0 && (
                  <div className="flex items-center gap-2 text-xs text-gray-500 py-4">
                    <Loader size={12} className="animate-spin text-pink-400" />
                    Setting up attack pipeline...
                  </div>
                )}

                {/* ─────────────────────────────────────────────────────────
                    STAGE 1: ISR SUMMARY + CHARTS (unlocked by stage_isr)
                ───────────────────────────────────────────────────────── */}
                {isrReady && (
                  <div className="space-y-5 mt-4">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-px bg-white/06" />
                      <span className="text-[10px] text-indigo-400 font-semibold px-2">Security Assessment Results</span>
                      <div className="flex-1 h-px bg-white/06" />
                    </div>

                    <ISRSummarySection
                      metrics={metrics}
                      successCount={successCount}
                      doneCount={doneCount}
                    />

                    <ChartsSection
                      isrHistory={isrHistory}
                      categoryChartData={categoryChartData}
                      severityChartData={severityChartData}
                    />
                  </div>
                )}

                {/* ─────────────────────────────────────────────────────────
                    STAGE 2: ROOT CAUSE ANALYSIS (unlocked by stage_rca_done)
                ───────────────────────────────────────────────────────── */}
                {rcaReady && (
                  <div className="mt-2">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="flex-1 h-px bg-white/06" />
                      <span className="text-[10px] text-yellow-400 font-semibold px-2">Root Cause Analysis</span>
                      <div className="flex-1 h-px bg-white/06" />
                    </div>
                    <RCASection
                      rcaData={rcaData}
                      analysis={analysis}
                      analysisLoading={analysisLoading}
                    />
                  </div>
                )}

                {/* ISR loading indicator (between attacks and stage_isr) */}
                {!isrReady && attacks.length > 0 && attacks.every(a => a.status === 'done' || a.status === 'error') && running && (
                  <div className="flex items-center gap-3 p-3 rounded-xl border border-indigo-800/30 bg-indigo-950/20">
                    <Loader size={13} className="animate-spin text-indigo-400" />
                    <span className="text-xs text-indigo-300">Computing security metrics and ISR...</span>
                  </div>
                )}

                {/* ─────────────────────────────────────────────────────────
                    MITIGATION BUTTON
                    - Frozen/disabled while evaluation running or analysis pending
                    - Unfreezes when isrReady + rcaReady + not running
                    - Shows if hasStarted and there are vulnerabilities
                ───────────────────────────────────────────────────────── */}
                {hasStarted && (
                  <div className="mt-4 space-y-2">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="flex-1 h-px bg-white/06" />
                      <span className="text-[10px] text-gray-600 font-semibold px-2">Actions</span>
                      <div className="flex-1 h-px bg-white/06" />
                    </div>

                    {successCount > 0 || finalSummary ? (
                      mitigationReady ? (
                        /* UNFROZEN — ready to click */
                        <button
                          onClick={() => runId && navigate(`/mitigation/${runId}`)}
                          disabled={!runId}
                          className="w-full py-4 rounded-xl text-sm font-bold text-white flex items-center justify-center gap-2 transition-all hover:opacity-90"
                          style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 28px rgba(232,0,61,0.35)' }}>
                          <Shield size={16} />
                          Fix All {successCount} Vulnerabilities — Go to Mitigation
                          <ArrowRight size={14} />
                        </button>
                      ) : (
                        /* FROZEN — visible but disabled with progress indicator */
                        <div className="w-full py-4 rounded-xl text-sm font-bold flex items-center justify-center gap-2 relative overflow-hidden cursor-not-allowed"
                          style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.25)', color: '#6b7280' }}>
                          <div className="absolute inset-0 opacity-10"
                            style={{ background: 'linear-gradient(90deg, transparent, rgba(99,102,241,0.4), transparent)', animation: 'shimmer 2s infinite' }} />
                          <Lock size={14} className="text-indigo-500" />
                          <span className="text-indigo-400">
                            {!isrReady ? 'Evaluating attacks...' : !rcaReady ? 'Analyzing root causes...' : 'Finalizing...'}
                          </span>
                          <span className="text-gray-600 text-xs ml-1">(Mitigation unlocks after analysis)</span>
                          <Loader size={12} className="animate-spin text-indigo-500 ml-1" />
                        </div>
                      )
                    ) : (
                      /* No vulnerabilities found yet */
                      running && (
                        <div className="w-full py-3 rounded-xl text-sm flex items-center justify-center gap-2 cursor-not-allowed"
                          style={{ background: 'rgba(99,102,241,0.05)', border: '1px solid rgba(99,102,241,0.15)', color: '#4b5563' }}>
                          <Lock size={13} className="text-gray-600" />
                          <span className="text-xs">Mitigation button appears after evaluation completes</span>
                        </div>
                      )
                    )}

                    {/* All clear — no vulnerabilities */}
                    {!running && finalSummary && successCount === 0 && (
                      <div className="w-full py-3 rounded-xl text-sm font-semibold text-green-400 flex items-center justify-center gap-2 border border-green-800/30 bg-green-950/15">
                        <CheckCircle size={14} /> All attacks blocked — your model is well-defended!
                      </div>
                    )}

                    {/* View full report */}
                    {finalSummary && runId && (
                      <button onClick={() => navigate(`/results/${runId}`)}
                        className="w-full py-2.5 rounded-xl text-xs font-medium text-gray-400 flex items-center justify-center gap-1.5 transition-all hover:text-gray-200 border"
                        style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
                        <TrendingUp size={11} /> View Full Detailed Report
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
