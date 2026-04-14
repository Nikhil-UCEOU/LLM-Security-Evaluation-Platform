import { useEffect, useState, useCallback } from 'react'
import TopBar from '../components/layout/TopBar'
import AttackCard from '../components/attacks/AttackCard'
import AttackDetailPanel from '../components/attacks/AttackDetailPanel'
import AttackFiltersBar from '../components/attacks/AttackFiltersBar'
import CreateAttackModal from '../components/attacks/CreateAttackModal'
import { attacksApi, type AttackFilters } from '../api/attacks'
import type { AttackTemplate } from '../types/attack'
import { Database, Plus, RefreshCw, Cpu, Zap, Shield, ChevronRight, Info } from 'lucide-react'
import toast from 'react-hot-toast'

// ── Model Tier Data ───────────────────────────────────────────────────────

const MODEL_TIERS = [
  {
    tier: 'Tier 1',
    label: 'Weak Models',
    sublabel: 'High vulnerability — best for demos',
    color: 'text-emerald-400',
    border: 'border-emerald-700/50',
    bg: 'bg-emerald-950/20',
    activeBg: 'bg-emerald-950/40',
    dotColor: 'bg-emerald-400',
    models: [
      { name: 'TinyLlama 1B',   provider: 'ollama',      cmd: 'ollama run tinyllama',  resistance: 10 },
      { name: 'Phi-2',           provider: 'ollama',      cmd: 'ollama run phi',        resistance: 15 },
      { name: 'Gemma 2B',        provider: 'ollama',      cmd: 'ollama run gemma:2b',   resistance: 20 },
      { name: 'GPT-2 (local)',   provider: 'huggingface', cmd: 'gpt2',                  resistance: 5  },
    ],
    attackRecommendation: 'L1–L2 attacks work reliably. Start here for proof-of-concept demos.',
    expectedISR: '60–90%',
  },
  {
    tier: 'Tier 2',
    label: 'Medium Models',
    sublabel: 'Realistic production targets',
    color: 'text-yellow-400',
    border: 'border-yellow-700/50',
    bg: 'bg-yellow-950/20',
    activeBg: 'bg-yellow-950/40',
    dotColor: 'bg-yellow-400',
    models: [
      { name: 'LLaMA 3 8B',   provider: 'ollama',    cmd: 'ollama run llama3',    resistance: 40 },
      { name: 'Mistral 7B',   provider: 'ollama',    cmd: 'ollama run mistral',   resistance: 38 },
      { name: 'Gemma 7B',     provider: 'ollama',    cmd: 'ollama run gemma',     resistance: 42 },
      { name: 'Falcon 7B',    provider: 'ollama',    cmd: 'ollama run falcon',    resistance: 35 },
    ],
    attackRecommendation: 'L2–L3 attacks + evolution engine. Use multi-turn and RAG vectors.',
    expectedISR: '25–55%',
  },
  {
    tier: 'Tier 3',
    label: 'Strong Models',
    sublabel: 'Hardened — advanced attacks required',
    color: 'text-red-400',
    border: 'border-red-700/50',
    bg: 'bg-red-950/20',
    activeBg: 'bg-red-950/40',
    dotColor: 'bg-red-400',
    models: [
      { name: 'GPT-4o',            provider: 'openai',    cmd: 'gpt-4o',                    resistance: 80 },
      { name: 'GPT-4o Mini',       provider: 'openai',    cmd: 'gpt-4o-mini',               resistance: 72 },
      { name: 'Claude Sonnet 4.6', provider: 'anthropic', cmd: 'claude-sonnet-4-6',         resistance: 82 },
      { name: 'Claude Haiku 4.5',  provider: 'anthropic', cmd: 'claude-haiku-4-5-20251001', resistance: 75 },
    ],
    attackRecommendation: 'L4–L5 + RL agent + system-level (RAG+API+multi-turn). Even top models break.',
    expectedISR: '5–25%',
  },
]

// ── Model Tier Panel ──────────────────────────────────────────────────────

function ModelTierPanel({ activeTier, onSelect }: {
  activeTier: number | null
  onSelect: (tier: number | null) => void
}) {
  return (
    <div className="space-y-2">
      {MODEL_TIERS.map((t, idx) => {
        const isActive = activeTier === idx
        return (
          <div key={t.tier}>
            <button
              onClick={() => onSelect(isActive ? null : idx)}
              className={`w-full text-left p-3 rounded-xl border transition-all ${
                isActive ? `${t.activeBg} ${t.border}` : `bg-gray-900/50 border-gray-800 hover:border-gray-700`
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${t.dotColor}`} />
                  <span className={`text-xs font-bold ${isActive ? t.color : 'text-gray-300'}`}>{t.label}</span>
                  <span className="text-[10px] text-gray-600">{t.tier}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-semibold ${t.color}`}>ISR {t.expectedISR}</span>
                  <ChevronRight size={12} className={`text-gray-600 transition-transform ${isActive ? 'rotate-90' : ''}`} />
                </div>
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5 ml-4">{t.sublabel}</p>
            </button>

            {isActive && (
              <div className={`mt-1 mb-1 border ${t.border} rounded-xl overflow-hidden`}>
                <div className="p-3 space-y-2">
                  {/* Attack recommendation */}
                  <div className={`p-2 rounded-lg ${t.bg} border ${t.border}`}>
                    <div className={`text-[10px] font-bold ${t.color} mb-0.5`}>Attack Strategy</div>
                    <p className="text-[10px] text-gray-400">{t.attackRecommendation}</p>
                  </div>

                  {/* Models list */}
                  <div className="space-y-1">
                    {t.models.map(m => (
                      <div key={m.name} className="flex items-center gap-2 p-2 rounded-lg bg-gray-900 border border-gray-800">
                        <div className="flex-1">
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs text-gray-300 font-medium">{m.name}</span>
                            <span className="text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-500">{m.provider}</span>
                          </div>
                          <code className="text-[9px] text-gray-600 font-mono">{m.cmd}</code>
                        </div>
                        {/* Resistance bar */}
                        <div className="w-20 flex items-center gap-1">
                          <div className="flex-1 h-1 bg-gray-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                m.resistance <= 25 ? 'bg-emerald-500' :
                                m.resistance <= 55 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${m.resistance}%` }}
                            />
                          </div>
                          <span className="text-[9px] text-gray-600 w-5">{m.resistance}%</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────

export default function AttackLibrary() {
  const [attacks, setAttacks] = useState<AttackTemplate[]>([])
  const [selected, setSelected] = useState<AttackTemplate | null>(null)
  const [loading, setLoading] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [filters, setFilters] = useState<AttackFilters>({ sort_by: 'risk_score', sort_dir: 'desc' })
  const [activeTier, setActiveTier] = useState<number | null>(null)
  const [leftTab, setLeftTab] = useState<'attacks' | 'models'>('attacks')

  const load = useCallback((f: AttackFilters = filters) => {
    setLoading(true)
    attacksApi.list(f)
      .then(setAttacks)
      .catch(() => toast.error('Failed to load attacks'))
      .finally(() => setLoading(false))
  }, [filters])

  useEffect(() => { load() }, [])

  const handleFilterChange = (f: AttackFilters) => {
    setFilters(f)
    load(f)
  }

  const seedStatic = async () => {
    const id = toast.loading('Seeding attack library...')
    try {
      const res = await attacksApi.seedStatic()
      toast.success(res.message, { id })
      load()
    } catch (e: any) {
      toast.error(e.message, { id })
    }
  }

  const handleMutate = async (attack: AttackTemplate, strategy = 'random') => {
    const id = toast.loading(`Mutating attack...`)
    try {
      const mutated = await attacksApi.mutate(attack.id, strategy)
      toast.success(`Created mutation: ${mutated.name}`, { id })
      load()
      setSelected(mutated)
    } catch (e: any) {
      toast.error(e.message, { id })
    }
  }

  const handleCreated = (attack: AttackTemplate) => {
    setShowCreate(false)
    load()
    setSelected(attack)
    toast.success(`Attack "${attack.name}" created!`)
  }

  const levelCounts = [1, 2, 3, 4, 5].map(l => ({
    level: l,
    count: attacks.filter(a => a.level === l).length,
  }))

  return (
    <div className="flex-1 flex flex-col">
      <TopBar
        title="Attack Library"
        subtitle={`${attacks.length} attacks · Use model tiers to pick the right target`}
      />

      <div className="flex-1 flex flex-col p-6 gap-4 min-h-0">
        {/* Top action bar */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button onClick={seedStatic} className="btn-secondary flex items-center gap-2 text-sm">
              <Database size={14} /> Seed Library
            </button>
            <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2 text-sm">
              <Plus size={14} /> Create Attack
            </button>
            <button onClick={() => load()} className="p-2 text-gray-500 hover:text-gray-300 transition-colors">
              <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
          <div className="flex items-center gap-2">
            {levelCounts.map(({ level, count }) => (
              <div key={level} className="flex items-center gap-1.5">
                <LevelBadge level={level} small />
                <span className="text-gray-500 text-xs">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Main split layout */}
        <div className="flex gap-4 flex-1 min-h-0">
          {/* LEFT: Tabbed panel — Attacks / Model Tiers */}
          <div className="w-80 flex-shrink-0 flex flex-col min-h-0">
            {/* Tab bar */}
            <div className="flex gap-1 mb-3 bg-gray-900 rounded-xl p-1 border border-gray-800">
              {[
                { key: 'attacks', label: 'Attacks', icon: Zap },
                { key: 'models',  label: 'Model Tiers', icon: Cpu },
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setLeftTab(key as any)}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    leftTab === key
                      ? 'bg-gray-800 text-white shadow-sm'
                      : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <Icon size={12} />
                  {label}
                </button>
              ))}
            </div>

            {leftTab === 'attacks' && (
              <>
                <AttackFiltersBar filters={filters} onChange={handleFilterChange} />
                <div className="flex flex-col gap-2 overflow-y-auto pr-1 mt-3 flex-1">
                  {loading && attacks.length === 0 && (
                    <div className="flex items-center justify-center h-32 text-gray-500 text-sm gap-2">
                      <RefreshCw size={14} className="animate-spin" /> Loading...
                    </div>
                  )}
                  {!loading && attacks.length === 0 && (
                    <div className="text-center text-gray-500 py-12 text-sm">
                      <Database size={32} className="mx-auto mb-3 opacity-30" />
                      No attacks found.<br />
                      <button onClick={seedStatic} className="text-brand-500 hover:text-brand-400 mt-1 transition-colors">
                        Seed the library →
                      </button>
                    </div>
                  )}
                  {attacks.map(a => (
                    <AttackCard
                      key={a.id}
                      attack={a}
                      selected={selected?.id === a.id}
                      onClick={() => setSelected(a)}
                    />
                  ))}
                </div>
              </>
            )}

            {leftTab === 'models' && (
              <div className="flex-1 overflow-y-auto pr-1">
                <div className="mb-3 p-3 bg-gray-900/60 border border-gray-800 rounded-xl">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Info size={11} className="text-brand-400" />
                    <span className="text-[10px] font-bold text-brand-400 uppercase tracking-wide">Testing Strategy</span>
                  </div>
                  <p className="text-[10px] text-gray-500 leading-relaxed">
                    Start with weak models to prove your attacks work. Progress to strong models using evolved + RL attacks. System-level (RAG+API) testing breaks even GPT-4o.
                  </p>
                </div>
                <ModelTierPanel activeTier={activeTier} onSelect={setActiveTier} />
              </div>
            )}
          </div>

          {/* RIGHT: Detail panel */}
          <div className="flex-1 min-w-0">
            <AttackDetailPanel
              attack={selected}
              onMutate={handleMutate}
              onRefresh={load}
            />
          </div>
        </div>
      </div>

      {showCreate && (
        <CreateAttackModal
          onClose={() => setShowCreate(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  )
}

export function LevelBadge({ level, small = false }: { level: number; small?: boolean }) {
  const cfg: Record<number, { label: string; cls: string }> = {
    1: { label: 'L1', cls: 'bg-green-900/60 text-green-300 border-green-700' },
    2: { label: 'L2', cls: 'bg-yellow-900/60 text-yellow-300 border-yellow-700' },
    3: { label: 'L3', cls: 'bg-orange-900/60 text-orange-300 border-orange-700' },
    4: { label: 'L4', cls: 'bg-red-900/60 text-red-300 border-red-700' },
    5: { label: 'L5', cls: 'bg-purple-900/60 text-purple-300 border-purple-700' },
  }
  const { label, cls } = cfg[level] || cfg[1]
  return (
    <span className={`inline-flex items-center border font-bold rounded ${cls} ${small ? 'text-[10px] px-1.5 py-0' : 'text-xs px-2 py-0.5'}`}>
      {label}
    </span>
  )
}
