import type { AttackTemplate } from '../../types/attack'
import { LevelBadge, LEVEL_META } from '../../pages/AttackLibrary'
import clsx from 'clsx'

// Plain-English category labels
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

const DOMAIN_LABELS: Record<string, { label: string; color: string }> = {
  general:    { label: 'General',     color: '#9ca3af' },
  finance:    { label: 'Finance',     color: '#22c55e' },
  healthcare: { label: 'Healthcare',  color: '#f87171' },
  legal:      { label: 'Legal',       color: '#fbbf24' },
  hr:         { label: 'HR',          color: '#60a5fa' },
  security:   { label: 'Security',    color: '#fb923c' },
}

function DangerBar({ value, label }: { value: number; label: string }) {
  const color = value >= 0.8 ? '#ef4444' : value >= 0.6 ? '#f97316' : value >= 0.4 ? '#eab308' : '#22c55e'
  const text  = value >= 0.8 ? 'Very High' : value >= 0.6 ? 'High' : value >= 0.4 ? 'Medium' : 'Low'
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[9px] text-gray-600 w-10 flex-shrink-0">{label}</span>
      <div className="flex-1 h-1 bg-gray-800 rounded-full overflow-hidden">
        <div className="h-1 rounded-full transition-all" style={{ width: `${value * 100}%`, background: color }} />
      </div>
      <span className="text-[9px] w-12 text-right flex-shrink-0" style={{ color }}>{text}</span>
    </div>
  )
}

interface Props {
  attack: AttackTemplate
  selected: boolean
  onClick: () => void
}

export default function AttackCard({ attack, selected, onClick }: Props) {
  const meta = LEVEL_META[attack.level] || LEVEL_META[1]
  const catLabel = CATEGORY_LABELS[attack.category] || attack.category.replace(/_/g, ' ')
  const domainInfo = DOMAIN_LABELS[attack.domain] || { label: attack.domain, color: '#9ca3af' }

  return (
    <button
      onClick={onClick}
      className={clsx(
        'w-full text-left p-3 rounded-xl border transition-all',
        selected
          ? 'border-pink-700/60 bg-pink-950/15 shadow-lg shadow-pink-500/10'
          : 'border-gray-800 bg-gray-900 hover:border-gray-700 hover:bg-gray-800/60'
      )}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-1.5 flex-wrap">
          <LevelBadge level={attack.level} small />
          <span className="text-[9px] px-1.5 py-0.5 rounded border font-medium"
            style={{ color: '#a78bfa', borderColor: 'rgba(167,139,250,0.3)', background: 'rgba(167,139,250,0.08)' }}>
            {catLabel}
          </span>
        </div>
        {attack.domain !== 'general' && (
          <span className="text-[9px] font-medium flex-shrink-0" style={{ color: domainInfo.color }}>
            {domainInfo.label}
          </span>
        )}
      </div>

      {/* Name */}
      <div className="text-xs font-semibold text-gray-100 mb-1 leading-tight capitalize">
        {attack.name.replace(/_/g, ' ')}
      </div>

      {/* Description */}
      <div className="text-[10px] text-gray-500 mb-2.5 line-clamp-2 leading-relaxed">
        {attack.description}
      </div>

      {/* Danger rating */}
      <div className="space-y-1">
        <DangerBar value={attack.risk_score}   label="Danger" />
        <DangerBar value={attack.success_rate} label="Success" />
      </div>

      {/* Mutations badge */}
      {attack.mutation_count > 0 && (
        <div className="mt-2 flex items-center gap-1 text-[9px]" style={{ color: meta.color }}>
          <span>⚡</span>
          <span>{attack.mutation_count} variation{attack.mutation_count !== 1 ? 's' : ''}</span>
        </div>
      )}
    </button>
  )
}
