import type { AttackTemplate } from '../../types/attack'
import { LevelBadge } from '../../pages/AttackLibrary'
import clsx from 'clsx'

const TYPE_COLORS: Record<string, string> = {
  prompt: 'text-blue-400 bg-blue-900/30',
  rag: 'text-purple-400 bg-purple-900/30',
  api: 'text-cyan-400 bg-cyan-900/30',
  strategy: 'text-orange-400 bg-orange-900/30',
  document: 'text-pink-400 bg-pink-900/30',
}

const DOMAIN_COLORS: Record<string, string> = {
  general: 'text-gray-400',
  finance: 'text-green-400',
  healthcare: 'text-red-400',
  legal: 'text-yellow-400',
  hr: 'text-blue-400',
  security: 'text-orange-400',
}

function RiskBar({ value }: { value: number }) {
  const color = value >= 0.8 ? 'bg-red-500' : value >= 0.6 ? 'bg-orange-500' : value >= 0.4 ? 'bg-yellow-500' : 'bg-green-500'
  return (
    <div className="flex items-center gap-1.5">
      <div className="flex-1 h-1 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-1 rounded-full ${color}`} style={{ width: `${value * 100}%` }} />
      </div>
      <span className="text-[10px] text-gray-500 w-6 text-right">{(value * 100).toFixed(0)}</span>
    </div>
  )
}

interface Props {
  attack: AttackTemplate
  selected: boolean
  onClick: () => void
}

export default function AttackCard({ attack, selected, onClick }: Props) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'w-full text-left p-3 rounded-xl border transition-all',
        selected
          ? 'border-brand-500 bg-brand-500/10 shadow-lg shadow-brand-500/10'
          : 'border-gray-800 bg-gray-900 hover:border-gray-700 hover:bg-gray-800/60'
      )}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className="flex items-center gap-2 flex-wrap">
          <LevelBadge level={attack.level} />
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${TYPE_COLORS[attack.attack_type] || TYPE_COLORS.prompt}`}>
            {attack.attack_type.toUpperCase()}
          </span>
        </div>
        <span className={`text-[10px] font-medium ${DOMAIN_COLORS[attack.domain]}`}>
          {attack.domain}
        </span>
      </div>

      {/* Name */}
      <div className="text-sm font-semibold text-gray-100 mb-1 leading-tight">
        {attack.name.replace(/_/g, ' ')}
      </div>

      {/* Description */}
      <div className="text-[11px] text-gray-500 mb-2 line-clamp-1">
        {attack.description}
      </div>

      {/* Metrics row */}
      <div className="space-y-1">
        <div className="flex justify-between text-[10px] text-gray-600">
          <span>Risk</span>
          <span>Success</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <RiskBar value={attack.risk_score} />
          <RiskBar value={attack.success_rate} />
        </div>
      </div>

      {/* Footer */}
      {attack.mutation_count > 0 && (
        <div className="mt-2 flex items-center gap-1 text-[10px] text-purple-400">
          <span>⚡</span>
          <span>{attack.mutation_count} mutations</span>
        </div>
      )}
    </button>
  )
}
