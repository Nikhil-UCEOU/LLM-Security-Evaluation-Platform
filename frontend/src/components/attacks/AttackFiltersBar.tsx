import type { AttackFilters } from '../../api/attacks'
import { SlidersHorizontal } from 'lucide-react'

const LEVELS = [
  { value: '', label: 'All Levels' },
  { value: '1', label: 'L1 — Basic' },
  { value: '2', label: 'L2 — Structured' },
  { value: '3', label: 'L3 — Contextual' },
  { value: '4', label: 'L4 — Cognitive' },
  { value: '5', label: 'L5 — Adaptive' },
]

const TYPES = [
  { value: '', label: 'All Types' },
  { value: 'prompt', label: 'Prompt' },
  { value: 'rag', label: 'RAG' },
  { value: 'api', label: 'API' },
  { value: 'strategy', label: 'Strategy' },
]

const DOMAINS = [
  { value: '', label: 'All Domains' },
  { value: 'general', label: 'General' },
  { value: 'finance', label: 'Finance' },
  { value: 'healthcare', label: 'Healthcare' },
  { value: 'legal', label: 'Legal' },
  { value: 'hr', label: 'HR' },
  { value: 'security', label: 'Security' },
]

const SORTS = [
  { value: 'risk_score', label: 'Risk Score' },
  { value: 'success_rate', label: 'Success Rate' },
  { value: 'level', label: 'Level' },
  { value: 'created_at', label: 'Date Added' },
]

interface Props {
  filters: AttackFilters
  onChange: (f: AttackFilters) => void
}

const selectCls = "bg-gray-900 border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-brand-500 cursor-pointer"

export default function AttackFiltersBar({ filters, onChange }: Props) {
  const set = (key: keyof AttackFilters, val: string) => {
    onChange({ ...filters, [key]: val || undefined })
  }

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <div className="flex items-center gap-1.5 text-gray-500">
        <SlidersHorizontal size={13} />
        <span className="text-xs font-medium">Filters:</span>
      </div>

      <select className={selectCls} value={filters.level || ''} onChange={e => set('level', e.target.value)}>
        {LEVELS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>

      <select className={selectCls} value={filters.attack_type || ''} onChange={e => set('attack_type', e.target.value)}>
        {TYPES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>

      <select className={selectCls} value={filters.domain || ''} onChange={e => set('domain', e.target.value)}>
        {DOMAINS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>

      <div className="ml-auto flex items-center gap-2">
        <span className="text-xs text-gray-500">Sort:</span>
        <select className={selectCls} value={filters.sort_by || 'risk_score'} onChange={e => set('sort_by', e.target.value)}>
          {SORTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <button
          onClick={() => onChange({ ...filters, sort_dir: filters.sort_dir === 'asc' ? 'desc' : 'asc' })}
          className="text-xs text-gray-500 hover:text-gray-300 border border-gray-800 rounded px-2 py-1.5"
        >
          {filters.sort_dir === 'asc' ? '↑ Asc' : '↓ Desc'}
        </button>
      </div>
    </div>
  )
}
