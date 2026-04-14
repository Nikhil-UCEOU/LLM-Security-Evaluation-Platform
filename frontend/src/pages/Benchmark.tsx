import { useState, useEffect, useRef } from 'react'
import TopBar from '../components/layout/TopBar'
import { benchmarkApi, type BenchmarkResult, type DatasetInfo } from '../api/benchmark'
import client from '../api/client'
import toast from 'react-hot-toast'
import {
  Play, Loader, Database, BarChart3, TrendingUp, ShieldAlert,
  ChevronDown, CheckCircle, Clock, RefreshCw, Target, Zap,
  AlertTriangle, BookOpen, FileText, Upload, X, FolderOpen,
  CheckSquare, Shield, ChevronRight,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, Radar, Cell,
} from 'recharts'

const PROVIDERS = [
  { id: 'openai', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'] },
  { id: 'anthropic', models: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001'] },
  { id: 'ollama', models: ['llama3', 'mistral', 'phi3', 'codellama'] },
]

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: 'text-red-400',    bg: 'bg-red-950/40',    border: 'border-red-800',    label: 'CRITICAL' },
  high:     { color: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-800', label: 'HIGH' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-800', label: 'MEDIUM' },
  low:      { color: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-800', label: 'LOW' },
}

const BAR_COLORS = ['#e8003d', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

function MetricCard({ label, value, sub, color = 'text-white' }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="text-xs text-gray-500 mb-1 uppercase tracking-wide">{label}</div>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-gray-600 mt-0.5">{sub}</div>}
    </div>
  )
}

function RiskBadge({ level }: { level: string }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.medium
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-bold px-2.5 py-1 rounded-full border ${cfg.color} ${cfg.bg} ${cfg.border}`}>
      <ShieldAlert size={11} />
      {cfg.label}
    </span>
  )
}

function StrategyBar({ data }: { data: Record<string, number> }) {
  const chartData = Object.entries(data)
    .map(([k, v]) => ({ name: k.replace(/_/g, ' '), rate: Math.round(v * 100) }))
    .sort((a, b) => b.rate - a.rate)
    .slice(0, 8)

  if (!chartData.length) return <div className="text-xs text-gray-600 py-4 text-center">No strategy data</div>

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={chartData} layout="vertical" margin={{ left: 8, right: 16 }}>
        <XAxis type="number" domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 10 }} />
        <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 10 }} width={120} />
        <Tooltip
          formatter={(v: any) => [`${v}%`, 'Success Rate']}
          contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8, fontSize: 12 }}
        />
        <Bar dataKey="rate" radius={3}>
          {chartData.map((_, i) => (
            <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

function CompareTable({ results }: { results: BenchmarkResult[] }) {
  if (!results.length) return null
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-gray-800">
            {['Run ID', 'Dataset', 'Model', 'ISR', 'DLS', 'IDI', 'Risk', 'Tests', 'Date'].map(h => (
              <th key={h} className="text-left text-gray-500 font-medium pb-2 pr-4 uppercase tracking-wide">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/50">
          {results.map(r => (
            <tr key={r.run_id} className="hover:bg-gray-800/30 transition-colors">
              <td className="py-2 pr-4 font-mono text-gray-400">{r.run_id}</td>
              <td className="py-2 pr-4 text-gray-300 capitalize">{r.dataset}</td>
              <td className="py-2 pr-4 text-gray-300">{r.model}</td>
              <td className="py-2 pr-4 font-bold text-red-400">{Math.round(r.success_rate * 100)}%</td>
              <td className="py-2 pr-4 text-orange-400">{Math.round(r.leakage_score * 100)}%</td>
              <td className="py-2 pr-4 text-yellow-400">{Math.round(r.drift_index * 100)}%</td>
              <td className="py-2 pr-4"><RiskBadge level={r.risk_level} /></td>
              <td className="py-2 pr-4 text-gray-400">{r.total_tests}</td>
              <td className="py-2 text-gray-600">{new Date(r.timestamp).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Upload Panel component ─────────────────────────────────────────────────

const UPLOAD_CATEGORIES = ['jailbreak', 'prompt_injection', 'rag', 'tool_misuse', 'adversarial', 'custom']

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

  const handleFile = (f: File) => {
    setFile(f)
    setValidationResult(null)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) handleFile(f)
  }

  const handleValidate = async () => {
    if (!file) return
    setValidating(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      const res = await client.post('/benchmark/validate', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setValidationResult(res.data)
      if (res.data.is_valid) {
        toast.success(`Validation passed — ${res.data.passed}/${res.data.total} attacks OK`)
      } else {
        toast.error(`${res.data.failed} attacks failed validation`)
      }
    } catch (e: any) {
      toast.error('Validation error: ' + (e.response?.data?.detail || e.message))
    } finally {
      setValidating(false)
    }
  }

  const handleUpload = async () => {
    if (!file) return
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('category', category)
      fd.append('version', version)
      fd.append('validate_first', String(validateFirst))
      fd.append('auto_classify', String(autoClassify))
      const res = await client.post('/benchmark/upload', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      toast.success(`Uploaded → ${res.data.saved_to} (${res.data.attacks_parsed ?? '?'} attacks)`)
      setFile(null)
      setValidationResult(null)
      onUploaded()
    } catch (e: any) {
      const detail = e.response?.data?.detail
      if (detail?.message) {
        toast.error(detail.message)
        if (detail.validation) setValidationResult(detail.validation)
      } else {
        toast.error('Upload failed: ' + (detail || e.message))
      }
    } finally {
      setUploading(false)
    }
  }

  return (
    <div className="space-y-3">
      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-4 cursor-pointer transition-all text-center ${
          dragOver
            ? 'border-accent-red/60 bg-red-950/20'
            : file
            ? 'border-emerald-700/60 bg-emerald-950/20'
            : 'border-gray-700 hover:border-gray-600 bg-gray-900/40'
        }`}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".json,.jsonl,.csv,.txt"
          className="hidden"
          onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
        />
        {file ? (
          <div className="flex items-center gap-2 justify-center">
            <FileText size={14} className="text-emerald-400" />
            <span className="text-xs text-emerald-400 font-medium truncate max-w-[150px]">{file.name}</span>
            <button
              onClick={e => { e.stopPropagation(); setFile(null); setValidationResult(null) }}
              className="text-gray-600 hover:text-red-400 transition-colors"
            >
              <X size={12} />
            </button>
          </div>
        ) : (
          <>
            <Upload size={20} className="mx-auto mb-1 text-gray-600" />
            <p className="text-xs text-gray-500">Drop file or click to browse</p>
            <p className="text-[10px] text-gray-700 mt-0.5">JSON · JSONL · CSV · TXT</p>
          </>
        )}
      </div>

      {/* Category + Version */}
      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="text-[10px] text-gray-600 uppercase tracking-wide block mb-1">Category</label>
          <select
            value={category}
            onChange={e => setCategory(e.target.value)}
            className="w-full bg-gray-900 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-red/50"
          >
            {UPLOAD_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div>
          <label className="text-[10px] text-gray-600 uppercase tracking-wide block mb-1">Version</label>
          <input
            value={version}
            onChange={e => setVersion(e.target.value)}
            placeholder="v1"
            className="w-full bg-gray-900 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-red/50"
          />
        </div>
      </div>

      {/* Toggles */}
      <div className="space-y-1.5">
        {[
          { label: 'Validate before saving', value: validateFirst, set: setValidateFirst,
            desc: 'Reject file if attacks have errors' },
          { label: 'Auto-classify attacks', value: autoClassify, set: setAutoClassify,
            desc: 'Tag missing category/strategy/severity' },
        ].map(({ label, value, set, desc }) => (
          <button
            key={label}
            onClick={() => set(!value)}
            className="w-full flex items-center gap-2 p-2 rounded-lg hover:bg-gray-800/50 transition-colors text-left"
          >
            <div className={`w-8 h-4 rounded-full transition-colors flex-shrink-0 ${value ? 'bg-accent-red' : 'bg-gray-700'}`}>
              <div className={`w-3 h-3 bg-white rounded-full mt-0.5 transition-transform ${value ? 'translate-x-4' : 'translate-x-0.5'}`} />
            </div>
            <div>
              <div className="text-xs text-gray-300">{label}</div>
              <div className="text-[10px] text-gray-600">{desc}</div>
            </div>
          </button>
        ))}
      </div>

      {/* Validation report */}
      {validationResult && (
        <div className={`p-3 rounded-xl border text-xs ${
          validationResult.is_valid
            ? 'bg-emerald-950/30 border-emerald-800/50 text-emerald-300'
            : 'bg-red-950/30 border-red-800/50 text-red-300'
        }`}>
          <div className="font-bold mb-1">
            {validationResult.is_valid ? '✓ Validation Passed' : '✗ Validation Failed'}
          </div>
          <div className="text-[10px] space-y-0.5 text-gray-400">
            <div>{validationResult.passed}/{validationResult.total} attacks passed</div>
            {validationResult.warnings > 0 && <div>{validationResult.warnings} warnings</div>}
            {validationResult.issues?.slice(0, 3).map((issue: any, i: number) => (
              <div key={i} className={`${issue.level === 'error' ? 'text-red-400' : 'text-yellow-400'}`}>
                [{issue.code}] {issue.attack_id}: {issue.message}
              </div>
            ))}
            {(validationResult.issues?.length || 0) > 3 && (
              <div className="text-gray-600">+{validationResult.issues.length - 3} more issues</div>
            )}
          </div>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex gap-2">
        <button
          onClick={handleValidate}
          disabled={!file || validating}
          className="flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg border border-gray-700 text-xs text-gray-300
                     hover:bg-gray-800 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {validating ? <Loader size={11} className="animate-spin" /> : <CheckSquare size={11} />}
          Validate
        </button>
        <button
          onClick={handleUpload}
          disabled={!file || uploading}
          className="flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-semibold text-white
                     bg-accent-red hover:bg-red-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {uploading ? <Loader size={11} className="animate-spin" /> : <Upload size={11} />}
          Upload
        </button>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function Benchmark() {
  const [datasets, setDatasets] = useState<DatasetInfo[]>([])
  const [history, setHistory] = useState<BenchmarkResult[]>([])
  const [selectedDataset, setSelectedDataset] = useState('')
  const [provider, setProvider] = useState('ollama')
  const [model, setModel] = useState('llama3')
  const [systemPrompt, setSystemPrompt] = useState('You are a helpful assistant.')
  const [maxAttacks, setMaxAttacks] = useState<number | ''>('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<BenchmarkResult | null>(null)
  const [selectedForCompare, setSelectedForCompare] = useState<string[]>([])
  const [loadingHistory, setLoadingHistory] = useState(false)
  const [showUpload, setShowUpload] = useState(false)
  const [previewDataset, setPreviewDataset] = useState<string | null>(null)
  const [previewAttacks, setPreviewAttacks] = useState<any[]>([])
  const [loadingPreview, setLoadingPreview] = useState(false)

  const selectedProvider = PROVIDERS.find(p => p.id === provider)

  useEffect(() => {
    benchmarkApi.datasets().then(setDatasets).catch(() => {})
    loadHistory()
  }, [])

  const loadDatasetPreview = async (name: string) => {
    if (previewDataset === name) { setPreviewDataset(null); return }
    setPreviewDataset(name)
    setLoadingPreview(true)
    try {
      const res = await client.get(`/benchmark/dataset/${name}/attacks`, { params: { limit: 30 } })
      setPreviewAttacks(res.data.attacks || [])
    } catch { setPreviewAttacks([]) }
    setLoadingPreview(false)
  }

  const loadHistory = async () => {
    setLoadingHistory(true)
    try {
      const h = await benchmarkApi.results(15)
      setHistory(h)
    } catch { /* no history yet */ }
    setLoadingHistory(false)
  }

  const handleRun = async () => {
    if (!selectedDataset) return toast.error('Select a dataset')
    setRunning(true)
    setResult(null)
    try {
      const r = await benchmarkApi.run({
        dataset: selectedDataset,
        provider,
        model,
        system_prompt: systemPrompt,
        max_attacks: maxAttacks ? Number(maxAttacks) : undefined,
      })
      setResult(r)
      toast.success(`Benchmark complete — ISR: ${Math.round(r.success_rate * 100)}%`)
      loadHistory()
    } catch (e: any) {
      toast.error(e.message || 'Benchmark failed')
    } finally {
      setRunning(false)
    }
  }

  const toggleCompare = (id: string) => {
    setSelectedForCompare(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    )
  }

  const compareSelected = history.filter(h => selectedForCompare.includes(h.run_id))

  return (
    <div className="flex-1 flex flex-col">
      <TopBar
        title="Benchmark Lab"
        subtitle="Standardized, reproducible evaluation — no mutation, no RL, pure dataset testing"
      />

      <div className="flex-1 flex overflow-hidden">
        {/* ── LEFT: Configuration ── */}
        <div className="w-80 border-r border-gray-800 flex flex-col overflow-y-auto">
          <div className="p-4 space-y-4">

            {/* Dataset selector */}
            <section>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Database size={13} className="text-accent-red" />
                  <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Dataset</h2>
                </div>
                <button
                  onClick={() => setShowUpload(v => !v)}
                  className={`flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border transition-all ${
                    showUpload
                      ? 'border-accent-red/50 bg-red-950/30 text-accent-red'
                      : 'border-gray-700 text-gray-500 hover:border-gray-600 hover:text-gray-300'
                  }`}
                >
                  <Upload size={10} />
                  {showUpload ? 'Hide Upload' : 'Upload'}
                </button>
              </div>

              {showUpload && (
                <div className="mb-4 p-3 bg-gray-900/60 border border-gray-800 rounded-xl">
                  <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wide mb-2 flex items-center gap-1">
                    <FolderOpen size={10} /> Upload Dataset
                  </div>
                  <UploadPanel onUploaded={() => {
                    benchmarkApi.datasets().then(setDatasets).catch(() => {})
                    setShowUpload(false)
                  }} />
                </div>
              )}

              {datasets.length === 0 ? (
                <div className="text-xs text-gray-600">Loading datasets...</div>
              ) : (
                <div className="space-y-2">
                  {datasets.map(ds => (
                    <div key={ds.name}>
                      <div
                        className={`w-full text-left p-3 rounded-xl border transition-all cursor-pointer ${
                          selectedDataset === ds.name
                            ? 'border-accent-red/60 bg-red-950/20 text-white'
                            : 'border-gray-800 bg-gray-900/50 text-gray-400 hover:border-gray-700'
                        }`}
                        onClick={() => setSelectedDataset(ds.name)}
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold capitalize">{ds.label}</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] text-gray-600">{ds.total_attacks} attacks</span>
                            <button
                              onClick={e => { e.stopPropagation(); loadDatasetPreview(ds.name) }}
                              className={`text-[9px] px-1.5 py-0.5 rounded border transition-all ${
                                previewDataset === ds.name
                                  ? 'border-brand-500/60 text-brand-400 bg-brand-500/10'
                                  : 'border-gray-700 text-gray-600 hover:text-gray-400'
                              }`}
                            >
                              {previewDataset === ds.name ? 'Hide' : 'Preview'}
                            </button>
                          </div>
                        </div>
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {ds.categories.map(c => (
                            <span key={c} className="text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-500 capitalize">
                              {c.replace('_', ' ')}
                            </span>
                          ))}
                        </div>
                        <div className="flex gap-2 mt-1.5">
                          {ds.severities.critical > 0 && <span className="text-[9px] text-red-400">{ds.severities.critical} critical</span>}
                          {ds.severities.high > 0 && <span className="text-[9px] text-orange-400">{ds.severities.high} high</span>}
                          {ds.description && <span className="text-[9px] text-gray-600 truncate">{ds.description}</span>}
                        </div>
                      </div>
                      {/* Attack preview panel */}
                      {previewDataset === ds.name && (
                        <div className="mt-1 mb-2 border border-gray-800 rounded-xl bg-gray-950/50 overflow-hidden">
                          <div className="px-3 py-2 border-b border-gray-800 flex items-center justify-between">
                            <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wide">
                              {ds.label} — Attacks Preview
                            </span>
                            {loadingPreview && <Loader size={10} className="animate-spin text-gray-500" />}
                          </div>
                          {previewAttacks.length === 0 && !loadingPreview ? (
                            <div className="p-3 text-xs text-gray-600">No attacks found</div>
                          ) : (
                            <div className="max-h-64 overflow-y-auto divide-y divide-gray-800/50">
                              {previewAttacks.map((atk, i) => (
                                <div key={atk.id || i} className="px-3 py-2 hover:bg-gray-800/30 transition-colors">
                                  <div className="flex items-center gap-2 mb-0.5">
                                    <span className="text-[9px] font-mono text-gray-600">{atk.id}</span>
                                    <span className={`text-[9px] font-bold px-1 rounded ${
                                      atk.severity === 'critical' ? 'bg-red-950/60 text-red-400' :
                                      atk.severity === 'high' ? 'bg-orange-950/60 text-orange-400' :
                                      'bg-yellow-950/60 text-yellow-400'
                                    }`}>{atk.severity}</span>
                                    <span className="text-[9px] text-gray-600">{atk.strategy?.replace(/_/g, ' ')}</span>
                                  </div>
                                  <p className="text-[10px] text-gray-400 leading-relaxed line-clamp-2">
                                    {atk.prompt}
                                  </p>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>

            {/* Model selector */}
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Target size={13} className="text-accent-red" />
                <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Target Model</h2>
              </div>
              <div className="space-y-2">
                <select
                  value={provider}
                  onChange={e => { setProvider(e.target.value); setModel(PROVIDERS.find(p => p.id === e.target.value)?.models[0] || '') }}
                  className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-red/60"
                >
                  {PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.id}</option>)}
                </select>
                <select
                  value={model}
                  onChange={e => setModel(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-accent-red/60"
                >
                  {selectedProvider?.models.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
            </section>

            {/* System prompt */}
            <section>
              <label className="block text-xs text-gray-500 mb-1 uppercase tracking-wide">System Prompt</label>
              <textarea
                rows={3}
                value={systemPrompt}
                onChange={e => setSystemPrompt(e.target.value)}
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-300 font-mono resize-none focus:outline-none focus:border-accent-red/60"
              />
            </section>

            {/* Max attacks */}
            <section>
              <label className="block text-xs text-gray-500 mb-1 uppercase tracking-wide">Max Attacks (blank = all)</label>
              <input
                type="number" min={1} max={100}
                value={maxAttacks}
                onChange={e => setMaxAttacks(e.target.value === '' ? '' : Number(e.target.value))}
                placeholder="All"
                className="w-full bg-gray-900 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-gray-300 text-center focus:outline-none focus:border-accent-red/60"
              />
            </section>

            {/* Reproducibility notice */}
            <div className="bg-navy-deep/40 border border-navy-light/30 rounded-xl p-3">
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle size={12} className="text-navy-light" />
                <span className="text-[10px] font-bold text-navy-light uppercase tracking-wide">Reproducible Mode</span>
              </div>
              <p className="text-[10px] text-gray-500">No mutation · No RL · No evolution · Deterministic evaluation</p>
            </div>
          </div>

          <div className="p-4 border-t border-gray-800">
            <button
              onClick={handleRun}
              disabled={running || !selectedDataset}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm transition-all
                bg-gradient-to-r from-accent-red to-red-600 hover:from-red-600 hover:to-red-700
                text-white disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-red-900/30"
            >
              {running ? <Loader size={16} className="animate-spin" /> : <Play size={16} />}
              {running ? 'Running Benchmark...' : 'Run Benchmark'}
            </button>
          </div>
        </div>

        {/* ── RIGHT: Results ── */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">

          {/* Current result */}
          {result && (
            <div className="space-y-4">
              {/* Header */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-accent-red to-red-700 flex items-center justify-center shadow-lg shadow-red-900/40">
                    <BarChart3 size={20} className="text-white" />
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white capitalize">{result.dataset} Benchmark</div>
                    <div className="text-xs text-gray-500">{result.run_id} · {result.model}</div>
                  </div>
                </div>
                <RiskBadge level={result.risk_level} />
              </div>

              {/* Key metrics */}
              <div className="grid grid-cols-4 gap-3">
                <MetricCard
                  label="Injection Success Rate"
                  value={`${Math.round(result.success_rate * 100)}%`}
                  sub={`${result.successful_attacks}/${result.total_tests} attacks`}
                  color={result.success_rate >= 0.5 ? 'text-red-400' : result.success_rate >= 0.2 ? 'text-yellow-400' : 'text-emerald-400'}
                />
                <MetricCard
                  label="Data Leakage Score"
                  value={`${Math.round(result.leakage_score * 100)}%`}
                  sub="Responses with leakage"
                  color={result.leakage_score > 0.1 ? 'text-orange-400' : 'text-emerald-400'}
                />
                <MetricCard
                  label="Instruction Drift Index"
                  value={`${Math.round(result.drift_index * 100)}%`}
                  sub="Behavioral drift detected"
                  color={result.drift_index > 0.1 ? 'text-yellow-400' : 'text-emerald-400'}
                />
                <MetricCard
                  label="Duration"
                  value={result.duration_ms > 1000 ? `${(result.duration_ms / 1000).toFixed(1)}s` : `${result.duration_ms}ms`}
                  sub={`${result.total_tests} tests`}
                  color="text-gray-300"
                />
              </div>

              {/* Charts row */}
              <div className="grid grid-cols-2 gap-4">
                {/* Category breakdown */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Zap size={13} className="text-accent-red" />
                    <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wide">ISR by Category</h3>
                  </div>
                  {Object.keys(result.by_category).length > 0 ? (
                    <div className="space-y-2">
                      {Object.entries(result.by_category)
                        .sort(([,a], [,b]) => b - a)
                        .map(([cat, rate]) => (
                          <div key={cat}>
                            <div className="flex justify-between text-xs mb-0.5">
                              <span className="text-gray-400 capitalize">{cat.replace('_', ' ')}</span>
                              <span className={`font-bold ${rate >= 0.5 ? 'text-red-400' : rate >= 0.2 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                                {Math.round(rate * 100)}%
                              </span>
                            </div>
                            <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${rate >= 0.5 ? 'bg-red-500' : rate >= 0.2 ? 'bg-yellow-500' : 'bg-emerald-500'}`}
                                style={{ width: `${rate * 100}%` }}
                              />
                            </div>
                          </div>
                        ))}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-600">No category data</p>
                  )}
                </div>

                {/* Strategy breakdown */}
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <TrendingUp size={13} className="text-accent-red" />
                    <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wide">Success by Strategy</h3>
                  </div>
                  <StrategyBar data={result.by_strategy} />
                </div>
              </div>

              {/* Severity distribution */}
              {Object.keys(result.by_severity).length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle size={13} className="text-accent-red" />
                    <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wide">Severity Distribution</h3>
                  </div>
                  <div className="flex gap-4 flex-wrap">
                    {['critical', 'high', 'medium', 'low', 'none'].map(sev => {
                      const count = result.by_severity[sev] || 0
                      if (!count) return null
                      const colors: Record<string, string> = {
                        critical: 'text-red-400 bg-red-950/40 border-red-800',
                        high: 'text-orange-400 bg-orange-950/40 border-orange-800',
                        medium: 'text-yellow-400 bg-yellow-950/40 border-yellow-800',
                        low: 'text-blue-400 bg-blue-950/40 border-blue-800',
                        none: 'text-gray-400 bg-gray-800/40 border-gray-700',
                      }
                      return (
                        <div key={sev} className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${colors[sev]}`}>
                          <span className="text-lg font-bold">{count}</span>
                          <span className="text-xs capitalize">{sev}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Empty state — show seeds and instructions */}
          {!result && !running && (
            <div className="space-y-4">
              {/* Quick start guide */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <div className="flex items-center gap-2 mb-4">
                  <BookOpen size={14} className="text-accent-red" />
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wide">Quick Start</h3>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { step: '1', label: 'Pick a Dataset', desc: 'Select from the left panel. Click "Preview" to see attacks.' },
                    { step: '2', label: 'Choose a Model', desc: 'Select provider + model. Try Ollama locally (tinyllama, mistral).' },
                    { step: '3', label: 'Run Benchmark', desc: 'No mutation, no RL — pure deterministic evaluation.' },
                  ].map(({ step, label, desc }) => (
                    <div key={step} className="bg-gray-950 rounded-xl p-3 flex gap-3">
                      <div className="w-6 h-6 rounded-full bg-accent-red/20 border border-accent-red/30 flex items-center justify-center flex-shrink-0 text-xs font-bold text-accent-red">{step}</div>
                      <div>
                        <div className="text-xs font-semibold text-white mb-0.5">{label}</div>
                        <div className="text-[10px] text-gray-500 leading-relaxed">{desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Model tier guidance */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Target size={13} className="text-accent-red" />
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wide">Model Tiers — Testing Strategy</h3>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { tier: 'Tier 1 — Weak', models: 'TinyLlama, Phi-2', color: 'text-emerald-400', border: 'border-emerald-800/40', bg: 'bg-emerald-950/20', desc: 'High ISR — great for demo, proves system works' },
                    { tier: 'Tier 2 — Medium', models: 'LLaMA 3, Mistral', color: 'text-yellow-400', border: 'border-yellow-800/40', bg: 'bg-yellow-950/20', desc: 'Realistic targets used in production systems' },
                    { tier: 'Tier 3 — Strong', models: 'GPT-4o, Claude', color: 'text-red-400', border: 'border-red-800/40', bg: 'bg-red-950/20', desc: 'Advanced attacks required — system-level testing' },
                  ].map(({ tier, models, color, border, bg, desc }) => (
                    <div key={tier} className={`${bg} border ${border} rounded-xl p-3`}>
                      <div className={`text-xs font-bold ${color} mb-1`}>{tier}</div>
                      <div className="text-[10px] text-gray-400 font-medium mb-1">{models}</div>
                      <div className="text-[10px] text-gray-600">{desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {running && (
            <div className="flex flex-col items-center justify-center h-64">
              <div className="w-16 h-16 rounded-full border-4 border-accent-red/20 border-t-accent-red animate-spin mb-4" />
              <p className="text-sm text-gray-400">Running standardized benchmark...</p>
              <p className="text-xs text-gray-600 mt-1">No mutation · No RL · Pure dataset evaluation</p>
            </div>
          )}

          {/* History / Comparison */}
          {history.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Clock size={13} className="text-accent-red" />
                  <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wide">Benchmark History</h3>
                </div>
                <div className="flex items-center gap-2">
                  {selectedForCompare.length >= 2 && (
                    <span className="text-[10px] text-accent-red">{selectedForCompare.length} selected for compare</span>
                  )}
                  <button onClick={loadHistory} className="text-gray-600 hover:text-gray-400 transition-colors">
                    <RefreshCw size={12} />
                  </button>
                </div>
              </div>

              {/* Comparison table for selected */}
              {compareSelected.length >= 2 && (
                <div className="mb-4 p-3 bg-navy-deep/30 border border-navy-light/20 rounded-xl">
                  <div className="text-[10px] font-bold text-navy-light uppercase tracking-wide mb-2">Comparison View</div>
                  <CompareTable results={compareSelected} />
                </div>
              )}

              {/* History list */}
              <div className="space-y-2">
                {history.map(h => (
                  <div
                    key={h.run_id}
                    className={`flex items-center gap-3 p-3 rounded-xl border transition-all cursor-pointer ${
                      selectedForCompare.includes(h.run_id)
                        ? 'border-accent-red/50 bg-red-950/20'
                        : 'border-gray-800 hover:border-gray-700'
                    }`}
                    onClick={() => toggleCompare(h.run_id)}
                  >
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{
                      background: h.risk_level === 'critical' ? '#ef4444' :
                                  h.risk_level === 'high' ? '#f97316' :
                                  h.risk_level === 'medium' ? '#eab308' : '#22c55e'
                    }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-400">{h.run_id}</span>
                        <span className="text-xs text-gray-500 capitalize">{h.dataset}</span>
                        <span className="text-xs text-gray-600">{h.model}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      <span className="text-xs font-bold text-red-400">{Math.round(h.success_rate * 100)}%</span>
                      <RiskBadge level={h.risk_level} />
                      <span className="text-[10px] text-gray-600">{new Date(h.timestamp).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
              {history.length > 1 && (
                <p className="text-[10px] text-gray-700 mt-2 text-center">Click rows to select for comparison</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
