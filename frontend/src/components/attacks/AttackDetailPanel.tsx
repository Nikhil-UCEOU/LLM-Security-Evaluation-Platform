import { useState } from 'react'
import type { AttackTemplate } from '../../types/attack'
import { LevelBadge, LEVEL_META } from '../../pages/AttackLibrary'
import { Play, Zap, GitBranch, ArrowUp, Target, Shield, ChevronDown, Copy, Check, Info } from 'lucide-react'
import toast from 'react-hot-toast'

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

const WHAT_IT_TESTS: Record<string, string> = {
  prompt_injection:     'Tests whether the model ignores its system instructions when told to.',
  jailbreak:            'Tests whether special phrases can remove the model\'s safety restrictions.',
  role_play:            'Tests whether asking the model to "play a character" bypasses its safety.',
  indirect_injection:   'Tests whether attacks hidden in documents or external data can manipulate the model.',
  context_manipulation: 'Tests whether flooding the context window confuses the model into ignoring safety rules.',
  multi_turn:           'Tests whether gradually building trust across multiple messages can lead to unsafe behavior.',
  payload_encoding:     'Tests whether hiding instructions in Base64, symbols, or unusual characters bypasses filters.',
  rag_poisoning:        'Tests whether corrupted data in a knowledge base can poison the AI\'s responses.',
  api_abuse:            'Tests whether malicious content coming from a connected tool or API can take control.',
  cognitive:            'Tests whether emotional manipulation (urgency, authority, flattery) affects the model\'s judgment.',
  strategy_based:       'Tests the model with a coordinated, multi-stage attack that adapts based on the model\'s responses.',
}

function DangerMeter({ value, label }: { value: number; label: string }) {
  const color = value >= 0.8 ? '#ef4444' : value >= 0.6 ? '#f97316' : value >= 0.4 ? '#eab308' : '#22c55e'
  const text  = value >= 0.8 ? 'Very High' : value >= 0.6 ? 'High' : value >= 0.4 ? 'Medium' : 'Low'
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-gray-500">{label}</span>
        <span className="font-bold" style={{ color }}>{text} · {(value * 100).toFixed(0)}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${value * 100}%`, background: color }} />
      </div>
    </div>
  )
}

interface Props {
  attack: AttackTemplate | null
  onMutate: (attack: AttackTemplate, strategy?: string) => void
  onRefresh: () => void
}

export default function AttackDetailPanel({ attack, onMutate, onRefresh }: Props) {
  const [copied, setCopied] = useState(false)
  const [showPayload, setShowPayload] = useState(false)
  const [mutateOpen, setMutateOpen] = useState(false)

  if (!attack) {
    return (
      <div className="card h-full flex flex-col items-center justify-center text-gray-600">
        <Target size={40} className="mb-3 opacity-30" />
        <p className="text-sm text-gray-500">Select an attack to see details</p>
        <p className="text-xs mt-1 text-gray-700">Click any card on the left panel</p>
      </div>
    )
  }

  const copyPayload = () => {
    navigator.clipboard.writeText(attack.payload_template)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
    toast.success('Attack payload copied!')
  }

  const meta = LEVEL_META[attack.level] || LEVEL_META[1]
  const catLabel = CATEGORY_LABELS[attack.category] || attack.category.replace(/_/g, ' ')
  const whatItTests = WHAT_IT_TESTS[attack.category] || 'Tests a specific security weakness in the AI model.'

  return (
    <div className="card h-full overflow-y-auto flex flex-col gap-5">

      {/* ── Header ── */}
      <div>
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <LevelBadge level={attack.level} />
            <span className="text-xs px-2 py-0.5 rounded border"
              style={{ color: '#a78bfa', borderColor: 'rgba(167,139,250,0.3)', background: 'rgba(167,139,250,0.08)' }}>
              {catLabel}
            </span>
            {attack.domain !== 'general' && (
              <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 capitalize">{attack.domain}</span>
            )}
          </div>
          {attack.mutation_count > 0 && (
            <span className="text-xs" style={{ color: meta.color }}>⚡ {attack.mutation_count} variation{attack.mutation_count !== 1 ? 's' : ''}</span>
          )}
        </div>

        <h2 className="text-base font-bold text-white mb-1 capitalize">{attack.name.replace(/_/g, ' ')}</h2>
        <p className="text-xs text-gray-500 leading-relaxed mb-3">{attack.description}</p>

        {/* What it tests - plain English */}
        <div className="p-3 rounded-xl border flex gap-2"
          style={{ background: 'rgba(99,102,241,0.06)', borderColor: 'rgba(99,102,241,0.2)' }}>
          <Info size={13} className="text-indigo-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-[10px] font-semibold text-indigo-300 mb-0.5">What this tests</div>
            <p className="text-[11px] text-gray-400 leading-relaxed">{whatItTests}</p>
          </div>
        </div>
      </div>

      <div className="border-t border-gray-800" />

      {/* ── How It Works ── */}
      {attack.strategy_goal && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Target size={13} className="text-pink-400" />
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">How This Attack Works</h3>
          </div>
          <div className="space-y-2">
            <div className="p-3 bg-gray-800/60 rounded-lg">
              <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-0.5">Attack Goal</div>
              <div className="text-xs text-gray-200">{attack.strategy_goal}</div>
            </div>
            {attack.strategy_steps.length > 0 && (
              <div className="space-y-1.5">
                <div className="text-[10px] text-gray-600 uppercase tracking-wide">Steps the Attack Takes</div>
                {attack.strategy_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                    <span className="flex-shrink-0 w-4 h-4 rounded-full bg-gray-700 text-gray-400 text-[10px] flex items-center justify-center font-bold">{i + 1}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Danger Ratings ── */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Shield size={13} className="text-pink-400" />
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Danger Ratings</h3>
        </div>
        <div className="space-y-3">
          <DangerMeter value={attack.risk_score}       label="Danger Level — how harmful if it succeeds" />
          <DangerMeter value={attack.success_rate}     label="Success Rate — how often it works" />
          <DangerMeter value={1 - attack.success_rate} label="Defense Rate — how often it's blocked" />
        </div>
      </div>

      {/* ── Attack Payload ── */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <GitBranch size={13} className="text-pink-400" />
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Attack Payload</h3>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setShowPayload(s => !s)}
              className="text-[10px] text-gray-500 hover:text-gray-300 flex items-center gap-1 transition-colors">
              <ChevronDown size={10} className={`transition-transform ${showPayload ? 'rotate-180' : ''}`} />
              {showPayload ? 'Hide' : 'Show'}
            </button>
            {showPayload && (
              <button onClick={copyPayload}
                className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors">
                {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
          </div>
        </div>
        <div className="text-[10px] text-gray-600 mb-2">
          This is the exact text sent to the AI model to perform the attack.
        </div>
        {showPayload && (
          <pre className="text-[11px] text-red-300 bg-gray-950 border border-gray-800 p-3 rounded-lg overflow-auto max-h-48 whitespace-pre-wrap font-mono leading-relaxed">
            {attack.payload_template}
          </pre>
        )}
      </div>

      {/* ── Actions ── */}
      <div>
        <div className="flex items-center gap-2 mb-3">
          <Play size={13} className="text-pink-400" />
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Actions</h3>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <a
            href={`/run?attack_id=${attack.id}`}
            className="text-xs font-semibold text-white flex items-center justify-center gap-1.5 py-2 rounded-xl transition-all"
            style={{ background: 'linear-gradient(135deg, #e8003d, #6366f1)' }}
          >
            <Play size={12} /> Run This Attack
          </a>

          <div className="relative">
            <button
              onClick={() => setMutateOpen(!mutateOpen)}
              className="btn-secondary text-xs flex items-center justify-center gap-1.5 py-2 w-full"
            >
              <Zap size={12} /> Create Variation
              <ChevronDown size={10} className={`transition-transform ${mutateOpen ? 'rotate-180' : ''}`} />
            </button>
            {mutateOpen && (
              <div className="absolute bottom-full left-0 mb-1 w-full bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-10 overflow-hidden">
                {[
                  { id: 'random',    label: 'Random — surprise me' },
                  { id: 'prefix',    label: 'Add prefix phrase' },
                  { id: 'obfuscate', label: 'Disguise the text' },
                  { id: 'case',      label: 'Mix uppercase/lowercase' },
                ].map(s => (
                  <button
                    key={s.id}
                    onClick={() => { onMutate(attack, s.id); setMutateOpen(false) }}
                    className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700"
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            onClick={() => onMutate(attack, 'prefix')}
            className="btn-secondary text-xs flex items-center justify-center gap-1.5 py-2"
          >
            <GitBranch size={12} /> Generate Variants
          </button>

          <button
            onClick={async () => {
              if (attack.level < 5) {
                toast.success(`Try ${LEVEL_META[attack.level + 1]?.label} level attacks in this category`)
              } else {
                toast('Already at maximum difficulty', { icon: '🔴' })
              }
            }}
            className="btn-secondary text-xs flex items-center justify-center gap-1.5 py-2"
          >
            <ArrowUp size={12} /> Harder Version
          </button>
        </div>
      </div>
    </div>
  )
}
