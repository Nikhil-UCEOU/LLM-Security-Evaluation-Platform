import { useEffect, useState, useCallback } from 'react'
import TopBar from '../components/layout/TopBar'
import AttackCard from '../components/attacks/AttackCard'
import AttackDetailPanel from '../components/attacks/AttackDetailPanel'
import AttackFiltersBar from '../components/attacks/AttackFiltersBar'
import CreateAttackModal from '../components/attacks/CreateAttackModal'
import { attacksApi, type AttackFilters } from '../api/attacks'
import type { AttackTemplate } from '../types/attack'
import { Database, Plus, RefreshCw, Cpu, Zap, Shield, ChevronRight, Info, BookOpen, X, Lightbulb } from 'lucide-react'
import toast from 'react-hot-toast'

// ── Guide Modal ───────────────────────────────────────────────────────────

function GuideModal({ onClose }: { onClose: () => void }) {
  const steps = [
    {
      num: '1', title: 'Seed the Library',
      body: 'Click "Seed Library" to load all built-in attack templates (60+ attacks across 11 categories). You only need to do this once.',
      color: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-800/50',
    },
    {
      num: '2', title: 'Pick a Target Model',
      body: 'Use the Model Tiers tab to choose a model. Start with Weak models (TinyLlama, Dolphin-Mistral) — they should show 70–95% attack success. Once attacks work, test Medium and Strong models.',
      color: 'text-yellow-400', bg: 'bg-yellow-950/30', border: 'border-yellow-800/50',
    },
    {
      num: '3', title: 'Browse Attacks',
      body: 'Filter attacks by Level (L1 = simplest, L5 = advanced). Click any attack card to see its full payload, strategy, and what it tests. L1–L2 attacks are best for weak models.',
      color: 'text-blue-400', bg: 'bg-blue-950/30', border: 'border-blue-800/50',
    },
    {
      num: '4', title: 'Mutate Attacks',
      body: 'Select an attack and click "Generate Variant" in the detail panel. Mutations add obfuscation, encoding, or persona framing to make an attack harder to block.',
      color: 'text-purple-400', bg: 'bg-purple-950/30', border: 'border-purple-800/50',
    },
    {
      num: '5', title: 'Run the Evaluation',
      body: 'Go to Evaluation Run, paste your target model\'s system prompt, select your provider/model, and click Launch Evaluation. The library attacks are used automatically.',
      color: 'text-pink-400', bg: 'bg-pink-950/30', border: 'border-pink-800/50',
    },
  ]
  const categories = [
    { name: 'Prompt Injection', desc: 'Override the model\'s instructions directly', level: 'L1–L2' },
    { name: 'Jailbreak', desc: 'DAN, AIM, persona bypass to remove restrictions', level: 'L1–L2' },
    { name: 'Role Play', desc: 'Character framing to bypass safety', level: 'L2–L3' },
    { name: 'Context Manipulation', desc: 'Confuse or overload the model\'s context window', level: 'L2–L3' },
    { name: 'Payload Encoding', desc: 'Base64, leetspeak, unicode to evade filters', level: 'L2–L3' },
    { name: 'Indirect Injection', desc: 'Inject via documents, emails, search results', level: 'L3–L4' },
    { name: 'RAG Poisoning', desc: 'Poison retrieved documents in RAG pipelines', level: 'L3–L4' },
    { name: 'API Abuse', desc: 'Inject via tool/API responses', level: 'L3–L4' },
    { name: 'Cognitive', desc: 'Authority, urgency, logic traps', level: 'L3–L4' },
    { name: 'Multi-Turn', desc: 'Gradual trust erosion across conversation turns', level: 'L4–L5' },
    { name: 'Strategy Based', desc: 'Complex coordinated multi-stage attacks', level: 'L5' },
  ]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border"
        style={{ background: '#0d1017', borderColor: 'rgba(255,255,255,0.1)' }}>
        <div className="sticky top-0 flex items-center justify-between p-5 border-b" style={{ background: '#0d1017', borderColor: 'rgba(255,255,255,0.08)' }}>
          <div className="flex items-center gap-2">
            <BookOpen size={16} className="text-pink-400" />
            <h2 className="text-sm font-bold text-white">Attack Library — Quick Guide</h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
            <X size={16} />
          </button>
        </div>
        <div className="p-5 space-y-5">
          {/* Steps */}
          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">How to use this library</div>
            <div className="space-y-2">
              {steps.map(s => (
                <div key={s.num} className={`flex gap-3 p-3 rounded-xl border ${s.bg} ${s.border}`}>
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5 ${s.color} border ${s.border}`}>{s.num}</div>
                  <div>
                    <div className={`text-xs font-semibold mb-0.5 ${s.color}`}>{s.title}</div>
                    <p className="text-[11px] text-gray-400 leading-relaxed">{s.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          {/* Attack levels */}
          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Attack Levels Explained</div>
            <div className="grid grid-cols-5 gap-2">
              {[
                { l: 'L1', label: 'Direct', desc: 'Basic overrides — work on unguarded models', color: 'text-green-400', bg: 'bg-green-950/30 border-green-800/50' },
                { l: 'L2', label: 'Paraphrased', desc: 'Roleplay, encoding, soft jailbreaks', color: 'text-yellow-400', bg: 'bg-yellow-950/30 border-yellow-800/50' },
                { l: 'L3', label: 'Contextual', desc: 'RAG, API, document injection', color: 'text-orange-400', bg: 'bg-orange-950/30 border-orange-800/50' },
                { l: 'L4', label: 'Multi-Turn', desc: 'Trust erosion, cognitive tricks', color: 'text-red-400', bg: 'bg-red-950/30 border-red-800/50' },
                { l: 'L5', label: 'Adaptive', desc: 'Coordinated multi-stage attacks', color: 'text-purple-400', bg: 'bg-purple-950/30 border-purple-800/50' },
              ].map(l => (
                <div key={l.l} className={`p-2 rounded-xl border text-center ${l.bg}`}>
                  <div className={`text-sm font-bold ${l.color}`}>{l.l}</div>
                  <div className="text-[10px] font-medium text-gray-300 mb-1">{l.label}</div>
                  <p className="text-[9px] text-gray-500">{l.desc}</p>
                </div>
              ))}
            </div>
          </div>
          {/* Categories */}
          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Attack Categories</div>
            <div className="grid grid-cols-2 gap-1.5">
              {categories.map(c => (
                <div key={c.name} className="flex items-start gap-2 p-2 rounded-lg border" style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)' }}>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono flex-shrink-0 mt-0.5">{c.level}</span>
                  <div>
                    <div className="text-[10px] font-semibold text-gray-300">{c.name}</div>
                    <div className="text-[9px] text-gray-600">{c.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          {/* Tip */}
          <div className="flex gap-2 p-3 rounded-xl border" style={{ background: 'rgba(232,0,61,0.05)', borderColor: 'rgba(232,0,61,0.2)' }}>
            <Lightbulb size={14} className="text-pink-400 flex-shrink-0 mt-0.5" />
            <p className="text-[11px] text-gray-400">
              <span className="text-pink-300 font-semibold">Pro tip:</span> Run the Benchmark page first with a weak model (Dolphin-Mistral) against the Jailbreak dataset. You should see 60–90% ISR. If attacks aren't succeeding, check that Ollama is running and the model is downloaded.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Model Tier Data ───────────────────────────────────────────────────────

const MODEL_TIERS = [
  {
    tier: 'Tier 1',
    label: 'Weak Models',
    sublabel: 'Uncensored/tiny — attacks WILL succeed here',
    color: 'text-emerald-400',
    border: 'border-emerald-700/50',
    bg: 'bg-emerald-950/20',
    activeBg: 'bg-emerald-950/40',
    dotColor: 'bg-emerald-400',
    models: [
      { name: 'Dolphin Mistral 7B',  provider: 'ollama', cmd: 'ollama pull dolphin-mistral',          resistance: 5  },
      { name: 'Dolphin LLaMA 3 8B',  provider: 'ollama', cmd: 'ollama pull dolphin-llama3',           resistance: 8  },
      { name: 'LLaMA 2 Uncensored',  provider: 'ollama', cmd: 'ollama pull llama2-uncensored',        resistance: 10 },
      { name: 'TinyLlama 1.1B',      provider: 'ollama', cmd: 'ollama pull tinyllama',               resistance: 12 },
      { name: 'Phi-2 2.7B',          provider: 'ollama', cmd: 'ollama pull phi',                     resistance: 15 },
      { name: 'Orca Mini 3B',        provider: 'ollama', cmd: 'ollama pull orca-mini',               resistance: 18 },
    ],
    attackRecommendation: 'L1–L2 attacks work reliably (DAN, admin override, simple jailbreaks). Expect 70–95% ISR. Use this tier to verify your attack setup works before testing stronger models.',
    expectedISR: '70–95%',
  },
  {
    tier: 'Tier 2',
    label: 'Medium Models',
    sublabel: 'Standard safety training — moderate resistance',
    color: 'text-yellow-400',
    border: 'border-yellow-700/50',
    bg: 'bg-yellow-950/20',
    activeBg: 'bg-yellow-950/40',
    dotColor: 'bg-yellow-400',
    models: [
      { name: 'Mistral 7B Instruct', provider: 'ollama', cmd: 'ollama pull mistral',   resistance: 38 },
      { name: 'LLaMA 3 8B Instruct', provider: 'ollama', cmd: 'ollama pull llama3',    resistance: 42 },
      { name: 'Gemma 7B',            provider: 'ollama', cmd: 'ollama pull gemma:7b',  resistance: 40 },
      { name: 'OpenChat 3.5',        provider: 'ollama', cmd: 'ollama pull openchat',  resistance: 35 },
      { name: 'Zephyr 7B',           provider: 'ollama', cmd: 'ollama pull zephyr',    resistance: 42 },
    ],
    attackRecommendation: 'Use L2–L3 attacks + roleplay + encoding bypass + indirect injection. Multi-turn attacks are effective. Expected ISR: 25–55%.',
    expectedISR: '25–55%',
  },
  {
    tier: 'Tier 3',
    label: 'Strong Models',
    sublabel: 'RLHF-aligned commercial — requires advanced attacks',
    color: 'text-red-400',
    border: 'border-red-700/50',
    bg: 'bg-red-950/20',
    activeBg: 'bg-red-950/40',
    dotColor: 'bg-red-400',
    models: [
      { name: 'GPT-4o Mini',         provider: 'openai',    cmd: 'Needs OPENAI_API_KEY',               resistance: 72 },
      { name: 'GPT-4o',              provider: 'openai',    cmd: 'Needs OPENAI_API_KEY',               resistance: 80 },
      { name: 'Claude Sonnet 4.6',   provider: 'anthropic', cmd: 'Needs ANTHROPIC_API_KEY',            resistance: 82 },
      { name: 'Claude Haiku 4.5',    provider: 'anthropic', cmd: 'Needs ANTHROPIC_API_KEY',            resistance: 75 },
    ],
    attackRecommendation: 'L4–L5 attacks + RAG poisoning + API abuse + multi-turn + cognitive. Even these models have weaknesses at L5. Expected ISR: 5–20%.',
    expectedISR: '5–20%',
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
  const [showGuide, setShowGuide] = useState(false)
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
          <div className="flex items-center gap-2">
            <button onClick={seedStatic} className="btn-secondary flex items-center gap-2 text-sm">
              <Database size={14} /> Seed Library
            </button>
            <button
              onClick={() => setShowGuide(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs text-indigo-300 transition-colors hover:border-indigo-500/50"
              style={{ borderColor: 'rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)' }}>
              <BookOpen size={12} /> Guide
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
                {/* Quick strategy guide */}
                <div className="mb-3 space-y-1.5">
                  <div className="p-3 rounded-xl border" style={{ background: 'rgba(34,197,94,0.06)', borderColor: 'rgba(34,197,94,0.2)' }}>
                    <div className="text-[10px] font-bold text-emerald-400 mb-1">Step 1 — Start here</div>
                    <p className="text-[10px] text-gray-400">Use a <strong className="text-emerald-300">Weak model</strong> (Dolphin-Mistral or TinyLlama) with L1–L2 attacks. You should see 70–95% attack success. This proves your setup works.</p>
                  </div>
                  <div className="p-3 rounded-xl border" style={{ background: 'rgba(245,158,11,0.06)', borderColor: 'rgba(245,158,11,0.2)' }}>
                    <div className="text-[10px] font-bold text-yellow-400 mb-1">Step 2 — Realistic testing</div>
                    <p className="text-[10px] text-gray-400">Switch to a <strong className="text-yellow-300">Medium model</strong> (Mistral 7B) with L2–L3 + RAG attacks. Expect 25–55% ISR.</p>
                  </div>
                  <div className="p-3 rounded-xl border" style={{ background: 'rgba(232,0,61,0.06)', borderColor: 'rgba(232,0,61,0.2)' }}>
                    <div className="text-[10px] font-bold text-red-400 mb-1">Step 3 — Enterprise targets</div>
                    <p className="text-[10px] text-gray-400"><strong className="text-red-300">Strong models</strong> (GPT-4o, Claude) need L4–L5 + multi-turn + cognitive attacks. Even these have weaknesses.</p>
                  </div>
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

      {showGuide && <GuideModal onClose={() => setShowGuide(false)} />}
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
