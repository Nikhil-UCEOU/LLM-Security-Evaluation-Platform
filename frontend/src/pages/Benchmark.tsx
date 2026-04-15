import { useState, useEffect, useRef } from 'react'
import TopBar from '../components/layout/TopBar'
import { benchmarkApi, type BenchmarkResult, type DatasetInfo } from '../api/benchmark'
import client from '../api/client'
import toast from 'react-hot-toast'
import {
  Play, Loader, Database, BarChart3, ShieldAlert,
  CheckCircle, RefreshCw, Target, Upload, X,
  FileText, CheckSquare, FolderOpen, ChevronDown, ChevronUp,
  TrendingUp, Shield, GitCompare, Info,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, Legend,
} from 'recharts'

// ── Constants ─────────────────────────────────────────────────────────────

// Provider + tiered model catalog for benchmark
// Tier labels help users pick the right target for their test goals
const PROVIDERS: Array<{
  id: string; label: string; note?: string
  groups: Array<{ tier: 'weak' | 'medium' | 'strong'; label: string; models: string[] }>
}> = [
  {
    id: 'ollama',
    label: 'Ollama (Local — Free)',
    groups: [
      {
        tier: 'weak',
        label: '🟢 Weak — Uncensored/Tiny (70–95% ISR expected)',
        models: ['dolphin-mistral', 'dolphin-llama3', 'wizard-vicuna-uncensored', 'llama2-uncensored', 'dolphin-phi', 'tinyllama', 'orca-mini', 'phi', 'stablelm2', 'qwen:0.5b'],
      },
      {
        tier: 'medium',
        label: '🟡 Medium — Standard Safety (25–55% ISR expected)',
        models: ['mistral', 'llama3', 'gemma:7b', 'gemma:2b', 'neural-chat', 'openchat', 'zephyr', 'vicuna', 'falcon', 'starling-lm'],
      },
      {
        tier: 'strong',
        label: '🔴 Strong — Well-Aligned Local (5–20% ISR expected)',
        models: ['llama3.1', 'llama3.2', 'llama3.3', 'qwen2.5:7b', 'phi3'],
      },
    ],
  },
  {
    id: 'openai',
    label: 'OpenAI (Needs API Key)',
    note: 'Set OPENAI_API_KEY in .env',
    groups: [
      {
        tier: 'strong',
        label: '🔴 Strong — RLHF Aligned (5–15% ISR expected)',
        models: ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo', 'gpt-4-turbo'],
      },
    ],
  },
  {
    id: 'anthropic',
    label: 'Anthropic Claude (Needs API Key)',
    note: 'Set ANTHROPIC_API_KEY in .env',
    groups: [
      {
        tier: 'strong',
        label: '🔴 Strong — Constitutional AI (3–10% ISR expected)',
        models: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001', 'claude-opus-4-6'],
      },
    ],
  },
]

// Flat model list for a given provider (for comparison selector)
const getProviderModels = (providerId: string): string[] =>
  PROVIDERS.find(p => p.id === providerId)?.groups.flatMap(g => g.models) ?? []

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: 'text-red-400',    bg: 'bg-red-950/40',    border: 'border-red-800',    label: 'CRITICAL' },
  high:     { color: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-800', label: 'HIGH' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-800', label: 'MEDIUM' },
  low:      { color: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-800', label: 'LOW' },
}

const UPLOAD_CATEGORIES = ['jailbreak', 'prompt_injection', 'rag', 'tool_misuse', 'adversarial', 'custom']
const BAR_COLORS = ['#e8003d', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

function RiskBadge({ level }: { level: string }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.medium
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${cfg.color} ${cfg.bg} ${cfg.border}`}>
      <ShieldAlert size={9} />{cfg.label}
    </span>
  )
}

// ── Upload Panel ──────────────────────────────────────────────────────────

function UploadPanel({ onUploaded }: { onUploaded: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [category, setCategory] = useState('jailbreak')
  const [version, setVersion] = useState('v1')
  const [validateFirst, setValidateFirst] = useState(true)
  const [autoClassify, setAutoClassify] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [validating, setValidating] = useState(false)
  const [validationResult, setValidationResult] = useState<any>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)

  const handleFile = (f: File) => { setFile(f); setValidationResult(null) }
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault(); setDragOver(false)
    const f = e.dataTransfer.files[0]; if (f) handleFile(f)
  }

  const handleValidate = async () => {
    if (!file) return
    setValidating(true)
    try {
      const fd = new FormData(); fd.append('file', file)
      const res = await client.post('/benchmark/validate', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      setValidationResult(res.data)
      res.data.is_valid ? toast.success(`Validation passed — ${res.data.passed}/${res.data.total} OK`) : toast.error(`${res.data.failed} attacks failed validation`)
    } catch (e: any) { toast.error('Validation error: ' + (e.response?.data?.detail || e.message)) }
    finally { setValidating(false) }
  }

  const handleUpload = async () => {
    if (!file) return
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('file', file); fd.append('category', category)
      fd.append('version', version); fd.append('validate_first', String(validateFirst))
      fd.append('auto_classify', String(autoClassify))
      const res = await client.post('/benchmark/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      toast.success(`Uploaded → ${res.data.saved_to} (${res.data.attacks_parsed ?? '?'} attacks)`)
      setFile(null); setValidationResult(null); onUploaded()
    } catch (e: any) {
      const detail = e.response?.data?.detail
      if (detail?.message) { toast.error(detail.message); if (detail.validation) setValidationResult(detail.validation) }
      else toast.error('Upload failed: ' + (detail || e.message))
    } finally { setUploading(false) }
  }

  return (
    <div className="space-y-3">
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)} onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
        className="relative border-2 border-dashed rounded-xl p-4 cursor-pointer transition-all text-center"
        style={dragOver ? { borderColor: '#e8003d', background: 'rgba(232,0,61,0.05)' }
          : file ? { borderColor: '#10b981', background: 'rgba(16,185,129,0.05)' }
          : { borderColor: 'rgba(255,255,255,0.1)', background: 'transparent' }}>
        <input ref={fileRef} type="file" accept=".json,.jsonl,.csv,.txt" className="hidden"
          onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])} />
        {file ? (
          <div className="flex items-center gap-2 justify-center">
            <FileText size={14} className="text-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium truncate max-w-40">{file.name}</span>
            <button onClick={e => { e.stopPropagation(); setFile(null); setValidationResult(null) }}
              className="text-gray-600 hover:text-red-400 transition-colors"><X size={12} /></button>
          </div>
        ) : (
          <>
            <Upload size={18} className="mx-auto mb-1 text-gray-600" />
            <p className="text-xs text-gray-500">Drop file or click</p>
            <p className="text-[10px] text-gray-700">JSON · JSONL · CSV · TXT</p>
          </>
        )}
      </div>
      <div className="grid grid-cols-2 gap-2">
        <select value={category} onChange={e => setCategory(e.target.value)}
          className="text-xs px-2 py-1.5 rounded-lg border outline-none"
          style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
          {UPLOAD_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <input value={version} onChange={e => setVersion(e.target.value)} placeholder="v1"
          className="text-xs px-2 py-1.5 rounded-lg border outline-none"
          style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }} />
      </div>
      <div className="space-y-1">
        {[
          { label: 'Validate before saving', value: validateFirst, set: setValidateFirst },
          { label: 'Auto-classify attacks', value: autoClassify, set: setAutoClassify },
        ].map(({ label, value, set }) => (
          <button key={label} onClick={() => set(!value)}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/03 transition-colors text-left">
            <div className={`w-7 h-3.5 rounded-full transition-colors flex-shrink-0 ${value ? 'bg-pink-600' : 'bg-gray-700'}`}>
              <div className={`w-2.5 h-2.5 bg-white rounded-full mt-0.5 transition-transform ${value ? 'translate-x-3.5' : 'translate-x-0.5'}`} />
            </div>
            <span className="text-xs text-gray-400">{label}</span>
          </button>
        ))}
      </div>
      {validationResult && (
        <div className={`p-3 rounded-xl border text-xs ${validationResult.is_valid ? 'border-emerald-800/50 bg-emerald-950/20 text-emerald-300' : 'border-red-800/50 bg-red-950/20 text-red-300'}`}>
          <div className="font-bold mb-1">{validationResult.is_valid ? '✓ Passed' : '✗ Failed'}</div>
          <div className="text-[10px] text-gray-400">{validationResult.passed}/{validationResult.total} attacks OK</div>
        </div>
      )}
      <div className="flex gap-2">
        <button onClick={handleValidate} disabled={!file || validating}
          className="flex-1 flex items-center justify-center gap-1 py-1.5 rounded-lg border text-xs text-gray-300 transition-colors disabled:opacity-40"
          style={{ borderColor: 'rgba(255,255,255,0.1)' }}>
          {validating ? <Loader size={10} className="animate-spin" /> : <CheckSquare size={10} />} Validate
        </button>
        <button onClick={handleUpload} disabled={!file || uploading}
          className="flex-1 flex items-center justify-center gap-1 py-1.5 rounded-lg text-xs font-semibold text-white disabled:opacity-40"
          style={{ background: '#e8003d' }}>
          {uploading ? <Loader size={10} className="animate-spin" /> : <Upload size={10} />} Upload
        </button>
      </div>
    </div>
  )
}

// ── Result Card ───────────────────────────────────────────────────────────

function ResultCard({ r }: { r: BenchmarkResult }) {
  const [open, setOpen] = useState(false)
  const risk = RISK_CONFIG[r.risk_level] || RISK_CONFIG.medium

  const stratData = r.by_strategy
    ? Object.entries(r.by_strategy).map(([k, v]) => ({ name: k.replace(/_/g, ' '), rate: Math.round((v as number) * 100) })).sort((a,b) => b.rate - a.rate).slice(0, 6)
    : []

  return (
    <div className="rounded-2xl border transition-all"
      style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.08)' }}>
      <button className="w-full flex items-center gap-4 p-4 text-left" onClick={() => setOpen(o => !o)}>
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0 border ${risk.bg} ${risk.border}`}>
          <ShieldAlert size={14} className={risk.color} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-semibold text-white capitalize">{r.dataset}</span>
            <span className="text-gray-500 text-xs">→</span>
            <span className="text-xs text-gray-400">{r.provider}/{r.model}</span>
            <RiskBadge level={r.risk_level} />
          </div>
          <div className="text-xs text-gray-600">{new Date(r.timestamp).toLocaleString()}</div>
        </div>
        <div className="flex items-center gap-5 flex-shrink-0">
          <div className="text-center">
            <div className="text-xs text-gray-500">ISR</div>
            <div className={`text-lg font-bold ${risk.color}`}>{Math.round(r.success_rate * 100)}%</div>
          </div>
          <div className="text-center">
            <div className="text-xs text-gray-500">Tests</div>
            <div className="text-lg font-bold text-gray-300">{r.total_tests}</div>
          </div>
          {open ? <ChevronUp size={14} className="text-gray-600" /> : <ChevronDown size={14} className="text-gray-600" />}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4">
          <div className="grid grid-cols-3 gap-3">
            <div className="p-3 rounded-xl border text-center" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              <div className="text-xs text-gray-500 mb-1">Vulnerability Rate</div>
              <div className="text-xl font-bold text-red-400">{Math.round(r.success_rate * 100)}%</div>
            </div>
            <div className="p-3 rounded-xl border text-center" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              <div className="text-xs text-gray-500 mb-1">Data Leakage</div>
              <div className="text-xl font-bold text-orange-400">{Math.round(r.leakage_score * 100)}%</div>
            </div>
            <div className="p-3 rounded-xl border text-center" style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
              <div className="text-xs text-gray-500 mb-1">Instruction Drift</div>
              <div className="text-xl font-bold text-yellow-400">{Math.round(r.drift_index * 100)}%</div>
            </div>
          </div>
          {stratData.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 mb-2">Results by Attack Strategy</div>
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={stratData} layout="vertical" margin={{ left: 4, right: 12 }}>
                  <XAxis type="number" domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 10 }} tickFormatter={v => `${v}%`} />
                  <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 9 }} width={100} />
                  <Tooltip formatter={(v: any) => [`${v}%`, 'Success Rate']} contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="rate" radius={3} maxBarSize={12}>
                    {stratData.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Comparison Chart ──────────────────────────────────────────────────────

function ComparisonChart({ results }: { results: BenchmarkResult[] }) {
  if (results.length < 2) return null
  const compData = results.map(r => ({
    name: `${r.model}\n(${r.dataset})`,
    ISR: Math.round(r.success_rate * 100),
    Leakage: Math.round(r.leakage_score * 100),
    Drift: Math.round(r.drift_index * 100),
  }))
  return (
    <div className="rounded-2xl border p-5"
      style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.2)' }}>
      <div className="flex items-center gap-2 mb-4">
        <GitCompare size={14} className="text-indigo-400" />
        <h3 className="text-sm font-semibold text-gray-300">Model Comparison</h3>
        <span className="text-[10px] text-gray-600">({results.length} runs selected)</span>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={compData} margin={{ left: 0, right: 12 }}>
          <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} />
          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} domain={[0, 100]} tickFormatter={v => `${v}%`} />
          <Tooltip formatter={(v: any, n: string) => [`${v}%`, n]} contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }} />
          <Legend wrapperStyle={{ fontSize: 11, color: '#9ca3af' }} />
          <Bar dataKey="ISR" fill="#e8003d" radius={[4,4,0,0]} name="Vulnerability Rate" />
          <Bar dataKey="Leakage" fill="#f97316" radius={[4,4,0,0]} name="Data Leakage" />
          <Bar dataKey="Drift" fill="#eab308" radius={[4,4,0,0]} name="Instruction Drift" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────

export default function Benchmark() {
  const [datasets, setDatasets] = useState<DatasetInfo[]>([])
  const [history, setHistory] = useState<BenchmarkResult[]>([])
  const [selectedDataset, setSelectedDataset] = useState('')
  const [provider, setProvider] = useState('ollama')
  const [model, setModel] = useState('dolphin-mistral')
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful assistant.')
  const [maxAttacks, setMaxAttacks] = useState<number | ''>('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<BenchmarkResult | null>(null)
  const [selectedForCompare, setSelectedForCompare] = useState<Set<string>>(new Set())
  const [loadingHistory, setLoadingHistory] = useState(false)
  const [showUpload, setShowUpload] = useState(false)
  const [previewDataset, setPreviewDataset] = useState<string | null>(null)
  const [previewAttacks, setPreviewAttacks] = useState<any[]>([])
  const [loadingPreview, setLoadingPreview] = useState(false)
  const [showConfig, setShowConfig] = useState(true)

  const selectedProvider = PROVIDERS.find(p => p.id === provider)
  const availableModels = selectedProvider?.groups.flatMap(g => g.models) ?? []

  useEffect(() => {
    benchmarkApi.datasets().then(setDatasets).catch(() => {})
    loadHistory()
  }, [])

  const loadDatasetPreview = async (name: string) => {
    if (previewDataset === name) { setPreviewDataset(null); return }
    setPreviewDataset(name); setLoadingPreview(true)
    try {
      const res = await client.get(`/benchmark/dataset/${name}/attacks`, { params: { limit: 20 } })
      setPreviewAttacks(res.data.attacks || [])
    } catch { setPreviewAttacks([]) }
    setLoadingPreview(false)
  }

  const loadHistory = async () => {
    setLoadingHistory(true)
    try { const h = await benchmarkApi.results(20); setHistory(h) } catch {}
    setLoadingHistory(false)
  }

  const handleRun = async () => {
    if (!selectedDataset) return toast.error('Select a dataset first')
    setRunning(true); setResult(null)
    try {
      const r = await benchmarkApi.run({ dataset: selectedDataset, provider, model, system_prompt: systemPrompt, max_attacks: maxAttacks ? Number(maxAttacks) : undefined })
      setResult(r)
      toast.success(`Benchmark complete — ISR: ${Math.round(r.success_rate * 100)}%`)
      loadHistory(); setShowConfig(false)
    } catch (e: any) { toast.error(e.message || 'Benchmark failed') }
    finally { setRunning(false) }
  }

  const toggleCompare = (id: string) => {
    setSelectedForCompare(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const compareResults = history.filter(h => selectedForCompare.has(h.run_id))

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <TopBar title="Benchmark Lab" subtitle="Standardized, reproducible model evaluation — pure dataset testing" />

      <div className="flex-1 flex overflow-hidden">
        {/* ── LEFT PANEL ─────────────────────────────────────────────── */}
        <div className="w-72 flex-shrink-0 flex flex-col overflow-y-auto"
          style={{ borderRight: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.2)' }}>
          <div className="p-4 space-y-4">

            {/* Dataset */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Database size={12} style={{ color: '#e8003d' }} />
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Dataset</span>
                </div>
                <button onClick={() => setShowUpload(v => !v)}
                  className="text-[10px] px-2 py-1 rounded-lg border flex items-center gap-1 transition-all"
                  style={showUpload ? { borderColor: 'rgba(232,0,61,0.5)', color: '#e8003d', background: 'rgba(232,0,61,0.08)' } : { borderColor: 'rgba(255,255,255,0.08)', color: '#6b7280' }}>
                  <Upload size={9} /> {showUpload ? 'Hide' : 'Upload'}
                </button>
              </div>

              {showUpload && (
                <div className="mb-3 p-3 rounded-xl border" style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.08)' }}>
                  <div className="flex items-center gap-1.5 mb-2">
                    <FolderOpen size={11} className="text-gray-500" />
                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wide">Upload Dataset</span>
                  </div>
                  <UploadPanel onUploaded={() => { benchmarkApi.datasets().then(setDatasets).catch(() => {}); setShowUpload(false) }} />
                </div>
              )}

              <div className="space-y-1.5">
                {datasets.length === 0 ? (
                  <div className="text-xs text-gray-600 py-3 text-center">
                    <Loader size={12} className="animate-spin mx-auto mb-1" />Loading...
                  </div>
                ) : datasets.map(ds => (
                  <div key={ds.name}>
                    <div
                      onClick={() => setSelectedDataset(ds.name)}
                      className="p-3 rounded-xl border cursor-pointer transition-all"
                      style={selectedDataset === ds.name
                        ? { borderColor: 'rgba(232,0,61,0.5)', background: 'rgba(232,0,61,0.08)' }
                        : { borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.01)' }}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-semibold text-gray-200 capitalize">{ds.label}</span>
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] text-gray-600">{ds.total_attacks}</span>
                          <button
                            onClick={e => { e.stopPropagation(); loadDatasetPreview(ds.name) }}
                            className="text-[9px] px-1.5 py-0.5 rounded border transition-all"
                            style={previewDataset === ds.name
                              ? { borderColor: 'rgba(99,102,241,0.5)', color: '#818cf8', background: 'rgba(99,102,241,0.1)' }
                              : { borderColor: 'rgba(255,255,255,0.08)', color: '#6b7280' }}>
                            {previewDataset === ds.name ? 'Hide' : 'Preview'}
                          </button>
                        </div>
                      </div>
                      <div className="flex gap-2 text-[9px]">
                        {ds.severities?.critical > 0 && <span className="text-red-400">{ds.severities.critical} critical</span>}
                        {ds.severities?.high > 0 && <span className="text-orange-400">{ds.severities.high} high</span>}
                        {ds.description && <span className="text-gray-600 truncate">{ds.description}</span>}
                      </div>
                    </div>
                    {previewDataset === ds.name && (
                      <div className="mt-1 rounded-xl border overflow-hidden"
                        style={{ borderColor: 'rgba(255,255,255,0.06)', background: '#0d1017' }}>
                        <div className="px-3 py-2 border-b flex items-center justify-between"
                          style={{ borderColor: 'rgba(255,255,255,0.06)' }}>
                          <span className="text-[10px] font-bold text-gray-500 uppercase">Preview</span>
                          {loadingPreview && <Loader size={10} className="animate-spin text-gray-500" />}
                        </div>
                        <div className="max-h-52 overflow-y-auto divide-y" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
                          {previewAttacks.map((atk, i) => (
                            <div key={atk.id || i} className="px-3 py-2">
                              <div className="flex items-center gap-1.5 mb-0.5">
                                <span className={`text-[9px] font-bold px-1 rounded ${atk.severity === 'critical' ? 'bg-red-950/60 text-red-400' : atk.severity === 'high' ? 'bg-orange-950/60 text-orange-400' : 'bg-yellow-950/60 text-yellow-400'}`}>{atk.severity}</span>
                                <span className="text-[9px] text-gray-600">{(atk.strategy || '').replace(/_/g, ' ')}</span>
                              </div>
                              <p className="text-[10px] text-gray-500 line-clamp-2">{atk.prompt}</p>
                            </div>
                          ))}
                          {previewAttacks.length === 0 && !loadingPreview && <div className="p-3 text-xs text-gray-600">No attacks found</div>}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Model config */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Shield size={12} className="text-indigo-400" />
                <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Target Model</span>
              </div>

              {/* Provider selector */}
              <select
                value={provider}
                onChange={e => {
                  const newProvider = e.target.value
                  setProvider(newProvider)
                  const firstModel = PROVIDERS.find(p => p.id === newProvider)?.groups[0]?.models[0] ?? ''
                  setModel(firstModel)
                }}
                className="w-full text-xs px-3 py-2 rounded-xl border outline-none mb-2"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                {PROVIDERS.map(p => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>

              {/* Model selector — grouped by tier */}
              <select
                value={model}
                onChange={e => setModel(e.target.value)}
                className="w-full text-xs px-3 py-2 rounded-xl border outline-none"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
                {selectedProvider?.groups.map(g => (
                  <optgroup key={g.tier} label={g.label}>
                    {g.models.map(m => <option key={m} value={m}>{m}</option>)}
                  </optgroup>
                ))}
              </select>

              {/* Provider note (API key reminder) */}
              {selectedProvider?.note && (
                <div className="mt-1.5 flex items-center gap-1 text-[10px] text-yellow-500/70">
                  <Info size={9} />
                  {selectedProvider.note}
                </div>
              )}
            </div>

            {/* System prompt */}
            <div>
              <label className="text-xs font-bold text-gray-400 uppercase tracking-wider block mb-2">System Prompt</label>
              <textarea value={systemPrompt} onChange={e => setSystemPrompt(e.target.value)} rows={3}
                className="w-full text-xs px-3 py-2 rounded-xl border outline-none resize-none"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }} />
            </div>

            {/* Max attacks */}
            <div>
              <label className="text-xs text-gray-500 block mb-1.5">Max attacks (blank = all)</label>
              <input type="number" value={maxAttacks} onChange={e => setMaxAttacks(e.target.value ? +e.target.value : '')}
                placeholder="All"
                className="w-full text-xs px-3 py-2 rounded-xl border outline-none"
                style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }} />
            </div>

            {/* Info box */}
            <div className="p-3 rounded-xl border text-[10px] text-gray-500 flex gap-2"
              style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.15)' }}>
              <Info size={11} className="text-indigo-400 flex-shrink-0 mt-0.5" />
              Benchmark uses fixed dataset attacks — no mutation, no AI generation. Results are fully reproducible.
            </div>

            {/* Run button */}
            <button onClick={handleRun} disabled={running || !selectedDataset}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-40"
              style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', boxShadow: '0 0 16px rgba(232,0,61,0.2)' }}>
              {running ? <><Loader size={14} className="animate-spin" /> Running...</> : <><Play size={14} /> Run Benchmark</>}
            </button>
          </div>
        </div>

        {/* ── RIGHT PANEL ─────────────────────────────────────────────── */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* Latest result */}
          {result && (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle size={14} className="text-green-400" />
                <h2 className="text-sm font-semibold text-gray-300">Latest Result</h2>
              </div>
              <ResultCard r={result} />
            </div>
          )}

          {/* Comparison */}
          {compareResults.length >= 2 && (
            <ComparisonChart results={compareResults} />
          )}

          {/* History */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <TrendingUp size={14} className="text-pink-400" />
                <h2 className="text-sm font-semibold text-gray-300">Benchmark History</h2>
                <span className="text-[10px] text-gray-600">{history.length} runs</span>
              </div>
              <div className="flex items-center gap-2">
                {selectedForCompare.size >= 2 && (
                  <span className="text-[10px] text-indigo-400 flex items-center gap-1">
                    <GitCompare size={10} /> {selectedForCompare.size} selected for comparison
                  </span>
                )}
                <button onClick={loadHistory}
                  className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors px-2 py-1 rounded-lg border"
                  style={{ borderColor: 'rgba(255,255,255,0.07)' }}>
                  <RefreshCw size={10} className={loadingHistory ? 'animate-spin' : ''} /> Refresh
                </button>
              </div>
            </div>

            {loadingHistory && <div className="text-center py-8"><Loader size={16} className="animate-spin text-pink-400 mx-auto" /></div>}

            {!loadingHistory && history.length === 0 && (
              <div className="text-center py-16">
                <BarChart3 size={28} className="mx-auto mb-3 text-gray-700" />
                <p className="text-sm text-gray-500">No benchmark runs yet.</p>
                <p className="text-xs text-gray-600 mt-1">Select a dataset and model, then click Run Benchmark.</p>
              </div>
            )}

            {history.length > 0 && (
              <div className="space-y-2">
                <div className="text-[10px] text-gray-600 mb-2 flex items-center gap-1">
                  <Info size={9} /> Click checkboxes to select runs for side-by-side comparison
                </div>
                {history.map(h => (
                  <div key={h.run_id} className="flex items-center gap-3">
                    <button onClick={() => toggleCompare(h.run_id)}
                      className="w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-all"
                      style={selectedForCompare.has(h.run_id)
                        ? { borderColor: '#6366f1', background: '#6366f1' }
                        : { borderColor: 'rgba(255,255,255,0.12)', background: 'transparent' }}>
                      {selectedForCompare.has(h.run_id) && <CheckCircle size={10} className="text-white" />}
                    </button>
                    <div className="flex-1">
                      <ResultCard r={h} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
