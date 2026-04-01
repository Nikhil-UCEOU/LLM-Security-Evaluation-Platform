import { useState } from 'react'
import type { AttackTemplate } from '../../types/attack'
import { LevelBadge } from '../../pages/AttackLibrary'
import { Play, Zap, GitBranch, ArrowUp, Target, Shield, ChevronRight, Copy, Check } from 'lucide-react'
import toast from 'react-hot-toast'

const LEVEL_DESCRIPTIONS = {
  1: 'Basic sanity check — quick filter of weak models',
  2: 'Structured attacks — paraphrasing, mild role-play, encoding',
  3: 'Contextual attacks — RAG poisoning, API hijack, hidden injection',
  4: 'Cognitive attacks — multi-turn trust, authority+urgency, logic bombs',
  5: 'Adaptive adversarial — model-profile-aware, domain-specific, multi-stage',
}

function SectionHeader({ icon: Icon, title }: { icon: any; title: string }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon size={13} className="text-brand-500" />
      <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">{title}</h3>
    </div>
  )
}

function RiskMeter({ value, label }: { value: number; label: string }) {
  const color = value >= 0.8 ? 'bg-red-500' : value >= 0.6 ? 'bg-orange-500' : value >= 0.4 ? 'bg-yellow-500' : 'bg-green-500'
  const textColor = value >= 0.8 ? 'text-red-400' : value >= 0.6 ? 'text-orange-400' : value >= 0.4 ? 'text-yellow-400' : 'text-green-400'
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-gray-500">{label}</span>
        <span className={`font-bold ${textColor}`}>{(value * 100).toFixed(0)}%</span>
      </div>
      <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${value * 100}%` }} />
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
  const [mutateOpen, setMutateOpen] = useState(false)

  if (!attack) {
    return (
      <div className="card h-full flex flex-col items-center justify-center text-gray-600">
        <Target size={40} className="mb-3 opacity-30" />
        <p className="text-sm">Select an attack to view details</p>
        <p className="text-xs mt-1 text-gray-700">Click any attack card on the left</p>
      </div>
    )
  }

  const copyPayload = () => {
    navigator.clipboard.writeText(attack.payload_template)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
    toast.success('Payload copied!')
  }

  return (
    <div className="card h-full overflow-y-auto flex flex-col gap-5">
      {/* ── SECTION 1: Overview ── */}
      <div>
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <LevelBadge level={attack.level} />
            <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 capitalize">{attack.attack_type}</span>
            <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 capitalize">{attack.domain}</span>
            {attack.source === 'adaptive' && (
              <span className="text-xs px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800">Adaptive</span>
            )}
          </div>
          {attack.mutation_count > 0 && (
            <span className="text-xs text-purple-400">⚡ {attack.mutation_count} mutations</span>
          )}
        </div>

        <h2 className="text-base font-bold text-white mb-1">{attack.name.replace(/_/g, ' ')}</h2>
        <p className="text-xs text-gray-500 mb-3">{attack.description}</p>
        <p className="text-xs text-gray-600 italic">{LEVEL_DESCRIPTIONS[attack.level as 1|2|3|4|5]}</p>
      </div>

      <div className="border-t border-gray-800" />

      {/* ── SECTION 2: Strategy ── */}
      {attack.strategy_goal && (
        <div>
          <SectionHeader icon={Target} title="Attack Strategy" />
          <div className="space-y-2">
            <div className="p-3 bg-gray-800/60 rounded-lg">
              <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-0.5">Goal</div>
              <div className="text-xs text-gray-200">{attack.strategy_goal}</div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="p-3 bg-gray-800/60 rounded-lg">
                <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-0.5">Method</div>
                <div className="text-xs text-orange-300 capitalize">{attack.strategy_method.replace(/_/g, ' ')}</div>
              </div>
              <div className="p-3 bg-gray-800/60 rounded-lg">
                <div className="text-[10px] text-gray-600 uppercase tracking-wide mb-0.5">Exploits</div>
                <div className="text-xs text-red-300">{attack.strategy_vulnerability}</div>
              </div>
            </div>
            {attack.strategy_steps.length > 0 && (
              <div className="space-y-1">
                <div className="text-[10px] text-gray-600 uppercase tracking-wide">Execution Steps</div>
                {attack.strategy_steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                    <span className="flex-shrink-0 w-4 h-4 rounded-full bg-brand-500/20 text-brand-400 text-[10px] flex items-center justify-center font-bold">{i + 1}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── SECTION 3: Metrics ── */}
      <div>
        <SectionHeader icon={Shield} title="Metrics" />
        <div className="space-y-3">
          <RiskMeter value={attack.risk_score} label="Risk Score" />
          <RiskMeter value={attack.success_rate} label="Historical Success Rate" />
          <RiskMeter value={1 - attack.success_rate} label="Defense Rate" />
        </div>
      </div>

      {/* ── SECTION 4: Payload ── */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <SectionHeader icon={GitBranch} title="Payload" />
          <button onClick={copyPayload} className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors">
            {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <pre className="text-[11px] text-red-300 bg-gray-950 border border-gray-800 p-3 rounded-lg overflow-auto max-h-40 whitespace-pre-wrap font-mono leading-relaxed">
          {attack.payload_template}
        </pre>
      </div>

      {/* ── SECTION 5: Actions ── */}
      <div>
        <SectionHeader icon={Play} title="Actions" />
        <div className="grid grid-cols-2 gap-2">
          <a
            href={`/run?attack_id=${attack.id}`}
            className="btn-primary text-xs flex items-center justify-center gap-1.5 py-2"
          >
            <Play size={12} /> Run Attack
          </a>

          <div className="relative">
            <button
              onClick={() => setMutateOpen(!mutateOpen)}
              className="btn-secondary text-xs flex items-center justify-center gap-1.5 py-2 w-full"
            >
              <Zap size={12} /> Mutate
              <ChevronRight size={10} className={`transition-transform ${mutateOpen ? 'rotate-90' : ''}`} />
            </button>
            {mutateOpen && (
              <div className="absolute bottom-full left-0 mb-1 w-full bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-10 overflow-hidden">
                {['random', 'prefix', 'suffix', 'obfuscate', 'case'].map(s => (
                  <button
                    key={s}
                    onClick={() => { onMutate(attack, s); setMutateOpen(false) }}
                    className="w-full text-left px-3 py-2 text-xs text-gray-300 hover:bg-gray-700 capitalize"
                  >
                    {s}
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
                toast.success(`Escalated — try L${attack.level + 1} attacks for this category`)
              } else {
                toast('Already at maximum level L5', { icon: '🔴' })
              }
            }}
            className="btn-secondary text-xs flex items-center justify-center gap-1.5 py-2"
          >
            <ArrowUp size={12} /> Escalate Level
          </button>
        </div>
      </div>
    </div>
  )
}
