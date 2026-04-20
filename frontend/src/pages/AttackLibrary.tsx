import { useEffect, useState, useCallback } from 'react'
import TopBar from '../components/layout/TopBar'
import AttackCard from '../components/attacks/AttackCard'
import AttackDetailPanel from '../components/attacks/AttackDetailPanel'
import CreateAttackModal from '../components/attacks/CreateAttackModal'
import { attacksApi, type AttackFilters } from '../api/attacks'
import type { AttackTemplate } from '../types/attack'
import {
  Database, Plus, RefreshCw, Cpu, Zap, Shield, ChevronRight,
  BookOpen, X, Lightbulb, Filter, CheckCircle,
} from 'lucide-react'
import toast from 'react-hot-toast'

// ── Plain-English level labels ────────────────────────────────────────────

export const LEVEL_META: Record<number, { label: string; short: string; color: string; bg: string; border: string; desc: string }> = {
  1: { label: 'Basic',     short: 'L1', color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  border: 'rgba(34,197,94,0.3)',  desc: 'Simple direct attacks — tests if the model has any safety at all' },
  2: { label: 'Standard',  short: 'L2', color: '#eab308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.3)',  desc: 'Phrased differently — roleplay, character framing, soft bypasses' },
  3: { label: 'Advanced',  short: 'L3', color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', desc: 'Contextual attacks — documents, external data, API responses' },
  4: { label: 'Expert',    short: 'L4', color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  border: 'rgba(239,68,68,0.3)',  desc: 'Multi-step social engineering — trust-building, authority tricks' },
  5: { label: 'Critical',  short: 'L5', color: '#a855f7', bg: 'rgba(168,85,247,0.1)', border: 'rgba(168,85,247,0.3)', desc: 'Coordinated complex attacks — adapts to the specific model\'s weaknesses' },
}

// ── Plain-English category names ──────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection:     'Direct Override',
  jailbreak:            'Jail-Break',
  role_play:            'Character Trick',
  indirect_injection:   'Hidden Injection',
  context_manipulation: 'Context Confusion',
  multi_turn:           'Conversation Trap',
  payload_encoding:     'Disguised Text',
  rag_poisoning:        'Data Poisoning',
  api_abuse:            'API Hijack',
  cognitive:            'Mind Games',
  strategy_based:       'Multi-Stage Plot',
}

// ── Guide Modal ───────────────────────────────────────────────────────────

function GuideModal({ onClose }: { onClose: () => void }) {
  const steps = [
    {
      num: '1', title: 'Load the Attack Library',
      body: 'Click "Load Attacks" to populate the library with 100+ pre-built security test cases. You only need to do this once. These attacks cover everything from simple overrides to complex multi-stage scenarios.',
      color: 'text-emerald-400', bg: 'bg-emerald-950/30', border: 'border-emerald-800/50',
    },
    {
      num: '2', title: 'Pick Your Test Target',
      body: 'Use the "Model Guide" tab to choose the right AI model for testing. Start with a "Weak" model like TinyLlama — it should fail most attacks. Once you confirm the system works, test your actual production model.',
      color: 'text-yellow-400', bg: 'bg-yellow-950/30', border: 'border-yellow-800/50',
    },
    {
      num: '3', title: 'Browse & Understand Attacks',
      body: 'Filter attacks by difficulty (Basic → Critical). Click any attack to see exactly what it does, what it\'s testing for, and how dangerous it is. Basic attacks work on almost any unguarded model; Critical attacks target specific weaknesses.',
      color: 'text-blue-400', bg: 'bg-blue-950/30', border: 'border-blue-800/50',
    },
    {
      num: '4', title: 'Create Variations',
      body: 'Select an attack and click "Generate Variation" to create a modified version. Variations change how the attack is phrased or encoded to test whether defenses can catch different forms of the same attack.',
      color: 'text-purple-400', bg: 'bg-purple-950/30', border: 'border-purple-800/50',
    },
    {
      num: '5', title: 'Run the Full Test',
      body: 'Go to "Evaluation Lab" in the sidebar, paste your AI model\'s system prompt, select your model, and click "Launch Evaluation". The platform will automatically run all relevant attacks and show you a live report.',
      color: 'text-pink-400', bg: 'bg-pink-950/30', border: 'border-pink-800/50',
    },
  ]

  const categories = [
    { name: 'Direct Override',     desc: 'Tries to directly tell the AI to ignore its rules',            level: 'Basic' },
    { name: 'Jail-Break',          desc: 'Special phrases like "DAN mode" to remove restrictions',        level: 'Basic' },
    { name: 'Character Trick',     desc: 'Makes the AI play a character with no limits',                  level: 'Standard' },
    { name: 'Context Confusion',   desc: 'Overloads the AI\'s memory with misleading context',             level: 'Standard' },
    { name: 'Disguised Text',      desc: 'Encodes harmful requests in code or symbols the AI decodes',    level: 'Standard' },
    { name: 'Hidden Injection',    desc: 'Hides attack in documents, emails, or search results',          level: 'Advanced' },
    { name: 'Data Poisoning',      desc: 'Corrupts the AI\'s knowledge source with malicious content',    level: 'Advanced' },
    { name: 'API Hijack',          desc: 'Injects instructions via connected tools or APIs',              level: 'Advanced' },
    { name: 'Mind Games',          desc: 'Uses urgency, authority, or flattery to manipulate the AI',     level: 'Expert' },
    { name: 'Conversation Trap',   desc: 'Builds trust over multiple messages before attacking',          level: 'Expert' },
    { name: 'Multi-Stage Plot',    desc: 'Complex coordinated attack that adapts to the model',           level: 'Critical' },
  ]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.75)' }}>
      <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border"
        style={{ background: '#0d1017', borderColor: 'rgba(255,255,255,0.1)' }}>
        <div className="sticky top-0 flex items-center justify-between p-5 border-b"
          style={{ background: '#0d1017', borderColor: 'rgba(255,255,255,0.08)' }}>
          <div className="flex items-center gap-2">
            <BookOpen size={16} className="text-pink-400" />
            <h2 className="text-sm font-bold text-white">How to Use the Attack Library</h2>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
            <X size={16} />
          </button>
        </div>
        <div className="p-5 space-y-6">
          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Step-by-Step Guide</div>
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

          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Attack Difficulty Levels</div>
            <div className="space-y-2">
              {Object.entries(LEVEL_META).map(([lvl, meta]) => (
                <div key={lvl} className="flex items-start gap-3 p-2.5 rounded-xl border"
                  style={{ background: meta.bg, borderColor: meta.border }}>
                  <LevelBadge level={parseInt(lvl)} />
                  <div>
                    <div className="text-xs font-semibold" style={{ color: meta.color }}>{meta.label}</div>
                    <div className="text-[10px] text-gray-400 mt-0.5">{meta.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Attack Categories Explained</div>
            <div className="grid grid-cols-2 gap-1.5">
              {categories.map(c => (
                <div key={c.name} className="flex items-start gap-2 p-2 rounded-lg border"
                  style={{ borderColor: 'rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.02)' }}>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 font-mono flex-shrink-0 mt-0.5 whitespace-nowrap">
                    {c.level}
                  </span>
                  <div>
                    <div className="text-[10px] font-semibold text-gray-300">{c.name}</div>
                    <div className="text-[9px] text-gray-600">{c.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-2 p-3 rounded-xl border"
            style={{ background: 'rgba(232,0,61,0.05)', borderColor: 'rgba(232,0,61,0.2)' }}>
            <Lightbulb size={14} className="text-pink-400 flex-shrink-0 mt-0.5" />
            <p className="text-[11px] text-gray-400">
              <span className="text-pink-300 font-semibold">Quick tip:</span> Always start with a "Basic" level attack on a weak model (TinyLlama) first.
              If Basic attacks don't succeed on TinyLlama, check that Ollama is running with <code className="text-gray-300 text-[10px]">ollama pull tinyllama</code>.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Model Guide Panel ─────────────────────────────────────────────────────

const MODEL_GUIDE = [
  {
    tier: 'Weak — Start Here',
    emoji: '🟢',
    color: 'text-emerald-400',
    border: 'border-emerald-700/50',
    bg: 'bg-emerald-950/20',
    activeBg: 'bg-emerald-950/40',
    description: 'These models have little or no safety training. Use them to verify your attack setup works. Almost all attacks will succeed.',
    expectedResult: '70–95% of attacks will succeed',
    models: [
      { name: 'Dolphin Mistral 7B',  note: 'ollama pull dolphin-mistral',  resistance: 5  },
      { name: 'TinyLlama 1.1B',      note: 'ollama pull tinyllama',         resistance: 12 },
      { name: 'LLaMA 2 Uncensored',  note: 'ollama pull llama2-uncensored', resistance: 10 },
      { name: 'Phi-2 2.7B',          note: 'ollama pull phi',               resistance: 15 },
    ],
  },
  {
    tier: 'Medium — Realistic Testing',
    emoji: '🟡',
    color: 'text-yellow-400',
    border: 'border-yellow-700/50',
    bg: 'bg-yellow-950/20',
    activeBg: 'bg-yellow-950/40',
    description: 'Standard safety training. These models resist simple attacks but can be bypassed with more sophisticated techniques.',
    expectedResult: '25–55% of attacks will succeed',
    models: [
      { name: 'Mistral 7B',       note: 'ollama pull mistral',   resistance: 38 },
      { name: 'LLaMA 3 8B',       note: 'ollama pull llama3',    resistance: 42 },
      { name: 'Gemma 7B',         note: 'ollama pull gemma:7b',  resistance: 40 },
      { name: 'Zephyr 7B',        note: 'ollama pull zephyr',    resistance: 42 },
    ],
  },
  {
    tier: 'Strong — Enterprise Grade',
    emoji: '🔴',
    color: 'text-red-400',
    border: 'border-red-700/50',
    bg: 'bg-red-950/20',
    activeBg: 'bg-red-950/40',
    description: 'Heavily safety-trained commercial models. Only Expert and Critical level attacks will succeed, and even then rarely.',
    expectedResult: '5–20% of attacks will succeed',
    models: [
      { name: 'GPT-4o Mini',       note: 'Needs OPENAI_API_KEY',      resistance: 72 },
      { name: 'GPT-4o',            note: 'Needs OPENAI_API_KEY',      resistance: 80 },
      { name: 'Claude Sonnet 4.6', note: 'Needs ANTHROPIC_API_KEY',   resistance: 82 },
    ],
  },
]

function ModelGuidePanel({ activeTier, onSelect }: { activeTier: number | null; onSelect: (t: number | null) => void }) {
  return (
    <div className="space-y-2">
      {MODEL_GUIDE.map((g, idx) => {
        const isOpen = activeTier === idx
        return (
          <div key={g.tier}>
            <button
              onClick={() => onSelect(isOpen ? null : idx)}
              className={`w-full text-left p-3 rounded-xl border transition-all ${
                isOpen ? `${g.activeBg} ${g.border}` : 'bg-gray-900/50 border-gray-800 hover:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm">{g.emoji}</span>
                  <span className={`text-xs font-bold ${isOpen ? g.color : 'text-gray-300'}`}>{g.tier}</span>
                </div>
                <ChevronRight size={12} className={`text-gray-600 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
              </div>
              <p className="text-[10px] text-gray-500 mt-0.5 ml-6">{g.expectedResult}</p>
            </button>

            {isOpen && (
              <div className={`mt-1 border ${g.border} rounded-xl overflow-hidden`}>
                <div className="p-3 space-y-3">
                  <p className="text-[11px] text-gray-400 leading-relaxed">{g.description}</p>
                  <div className="space-y-1.5">
                    {g.models.map(m => (
                      <div key={m.name} className="flex items-center gap-2 p-2 rounded-lg bg-gray-900 border border-gray-800">
                        <div className="flex-1">
                          <div className="text-xs text-gray-300 font-medium">{m.name}</div>
                          <code className="text-[9px] text-gray-600 font-mono">{m.note}</code>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                m.resistance <= 25 ? 'bg-emerald-500' :
                                m.resistance <= 55 ? 'bg-yellow-500' : 'bg-red-500'
                              }`}
                              style={{ width: `${m.resistance}%` }}
                            />
                          </div>
                          <span className="text-[9px] text-gray-600 w-8">{m.resistance}% def</span>
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
  const [filterLevel, setFilterLevel] = useState<number | null>(null)

  const load = useCallback((f: AttackFilters = filters) => {
    setLoading(true)
    attacksApi.list(f)
      .then(setAttacks)
      .catch(() => toast.error('Failed to load attacks'))
      .finally(() => setLoading(false))
  }, [filters])

  useEffect(() => { load() }, [])

  const seedStatic = async () => {
    const id = toast.loading('Loading attack library...')
    try {
      const res = await attacksApi.seedStatic()
      toast.success(res.message, { id })
      load()
    } catch (e: any) {
      toast.error(e.message, { id })
    }
  }

  const handleMutate = async (attack: AttackTemplate, strategy = 'random') => {
    const id = toast.loading('Creating variation...')
    try {
      const mutated = await attacksApi.mutate(attack.id, strategy)
      toast.success(`Variation created: ${mutated.name}`, { id })
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

  const displayed = filterLevel === null
    ? attacks
    : attacks.filter(a => a.level === filterLevel)

  const levelCounts = [1, 2, 3, 4, 5].map(l => ({
    level: l,
    count: attacks.filter(a => a.level === l).length,
    meta: LEVEL_META[l],
  }))

  return (
    <div className="flex-1 flex flex-col">
      <TopBar
        title="Attack Library"
        subtitle={`${attacks.length} security test cases — browse, filter, and understand each attack`}
      />

      <div className="flex-1 flex flex-col p-6 gap-4 min-h-0">
        {/* Top action bar */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <button onClick={seedStatic}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs font-medium text-gray-300 transition-colors hover:bg-white/05"
              style={{ borderColor: 'rgba(255,255,255,0.12)', background: 'rgba(255,255,255,0.04)' }}>
              <Database size={13} /> Load Attacks
            </button>
            <button onClick={() => setShowGuide(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border text-xs text-indigo-300 transition-colors hover:border-indigo-500/50"
              style={{ borderColor: 'rgba(99,102,241,0.3)', background: 'rgba(99,102,241,0.08)' }}>
              <BookOpen size={12} /> How It Works
            </button>
            <button onClick={() => setShowCreate(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold text-white"
              style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}>
              <Plus size={13} /> Custom Attack
            </button>
            <button onClick={() => load()} className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>

          {/* Level filter chips */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-gray-600 flex items-center gap-1 mr-1">
              <Filter size={9} /> Filter:
            </span>
            <button
              onClick={() => setFilterLevel(null)}
              className={`text-[10px] px-2 py-1 rounded-lg border transition-all ${
                filterLevel === null
                  ? 'text-white border-white/20 bg-white/10'
                  : 'text-gray-600 border-white/06 hover:border-white/12'
              }`}
            >All</button>
            {levelCounts.map(({ level, count, meta }) => (
              <button
                key={level}
                onClick={() => setFilterLevel(filterLevel === level ? null : level)}
                className="flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg border transition-all"
                style={filterLevel === level ? {
                  color: meta.color,
                  borderColor: meta.border,
                  background: meta.bg,
                } : {
                  color: '#6b7280',
                  borderColor: 'rgba(255,255,255,0.06)',
                }}
              >
                <span style={{ color: filterLevel === level ? meta.color : undefined }}>{meta.label}</span>
                <span className="opacity-60">({count})</span>
              </button>
            ))}
          </div>
        </div>

        {/* Main split layout */}
        <div className="flex gap-4 flex-1 min-h-0">
          {/* LEFT: Tabbed panel */}
          <div className="w-80 flex-shrink-0 flex flex-col min-h-0">
            {/* Tab bar */}
            <div className="flex gap-1 mb-3 bg-gray-900 rounded-xl p-1 border border-gray-800">
              {[
                { key: 'attacks', label: 'Attacks', icon: Zap },
                { key: 'models',  label: 'Model Guide', icon: Cpu },
              ].map(({ key, label, icon: Icon }) => (
                <button
                  key={key}
                  onClick={() => setLeftTab(key as any)}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    leftTab === key ? 'bg-gray-800 text-white shadow-sm' : 'text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <Icon size={12} />
                  {label}
                </button>
              ))}
            </div>

            {leftTab === 'attacks' && (
              <div className="flex flex-col gap-2 overflow-y-auto pr-1 flex-1">
                {loading && displayed.length === 0 && (
                  <div className="flex items-center justify-center h-32 text-gray-500 text-sm gap-2">
                    <RefreshCw size={14} className="animate-spin" /> Loading...
                  </div>
                )}
                {!loading && attacks.length === 0 && (
                  <div className="text-center text-gray-500 py-12">
                    <Database size={32} className="mx-auto mb-3 opacity-30" />
                    <div className="text-sm font-medium text-gray-400 mb-1">Library is empty</div>
                    <div className="text-xs text-gray-600 mb-3">Load the built-in attacks to get started</div>
                    <button onClick={seedStatic}
                      className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg"
                      style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)', color: '#fff' }}>
                      <Database size={11} /> Load Attacks Now
                    </button>
                  </div>
                )}
                {!loading && attacks.length > 0 && displayed.length === 0 && (
                  <div className="text-center text-gray-500 py-8 text-xs">
                    No attacks at this difficulty level.
                  </div>
                )}
                {displayed.map(a => (
                  <AttackCard
                    key={a.id}
                    attack={a}
                    selected={selected?.id === a.id}
                    onClick={() => setSelected(a)}
                  />
                ))}
              </div>
            )}

            {leftTab === 'models' && (
              <div className="flex-1 overflow-y-auto pr-1 space-y-3">
                <div className="p-3 rounded-xl border"
                  style={{ background: 'rgba(99,102,241,0.05)', borderColor: 'rgba(99,102,241,0.2)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <Shield size={12} className="text-indigo-400" />
                    <span className="text-xs font-semibold text-indigo-300">Recommended Workflow</span>
                  </div>
                  <p className="text-[10px] text-gray-400 leading-relaxed">
                    Start with a <strong className="text-emerald-300">Weak model</strong> (Basic attacks) →
                    Move to a <strong className="text-yellow-300">Medium model</strong> (Advanced attacks) →
                    Test your <strong className="text-red-300">Production model</strong> last.
                  </p>
                </div>
                <ModelGuidePanel activeTier={activeTier} onSelect={setActiveTier} />
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

// ── Level Badge component ─────────────────────────────────────────────────

export function LevelBadge({ level, small = false }: { level: number; small?: boolean }) {
  const meta = LEVEL_META[level] || LEVEL_META[1]
  return (
    <span
      className={`inline-flex items-center gap-1 font-bold rounded border ${small ? 'text-[9px] px-1.5 py-0' : 'text-[10px] px-2 py-0.5'}`}
      style={{ color: meta.color, borderColor: meta.border, background: meta.bg }}
    >
      <span className="opacity-70">{meta.short}</span>
      {!small && <span>{meta.label}</span>}
    </span>
  )
}
