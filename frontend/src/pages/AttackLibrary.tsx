import { useEffect, useState, useCallback } from 'react'
import TopBar from '../components/layout/TopBar'
import AttackCard from '../components/attacks/AttackCard'
import AttackDetailPanel from '../components/attacks/AttackDetailPanel'
import AttackFiltersBar from '../components/attacks/AttackFiltersBar'
import CreateAttackModal from '../components/attacks/CreateAttackModal'
import { attacksApi, type AttackFilters } from '../api/attacks'
import type { AttackTemplate } from '../types/attack'
import { Database, Plus, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'

export default function AttackLibrary() {
  const [attacks, setAttacks] = useState<AttackTemplate[]>([])
  const [selected, setSelected] = useState<AttackTemplate | null>(null)
  const [loading, setLoading] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [filters, setFilters] = useState<AttackFilters>({ sort_by: 'risk_score', sort_dir: 'desc' })

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

  // Stats
  const levelCounts = [1, 2, 3, 4, 5].map(l => ({
    level: l,
    count: attacks.filter(a => a.level === l).length,
  }))

  return (
    <div className="flex-1 flex flex-col">
      <TopBar
        title="Attack Library"
        subtitle={`${attacks.length} attacks across 5 difficulty tiers`}
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

          {/* Level stats pills */}
          <div className="flex items-center gap-2">
            {levelCounts.map(({ level, count }) => (
              <div key={level} className="flex items-center gap-1.5">
                <LevelBadge level={level} small />
                <span className="text-gray-500 text-xs">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Filters */}
        <AttackFiltersBar filters={filters} onChange={handleFilterChange} />

        {/* Main split layout */}
        <div className="flex gap-4 flex-1 min-h-0">
          {/* LEFT: Attack list */}
          <div className="w-80 flex-shrink-0 flex flex-col gap-2 overflow-y-auto pr-1">
            {loading && attacks.length === 0 && (
              <div className="flex items-center justify-center h-32 text-gray-500 text-sm gap-2">
                <RefreshCw size={14} className="animate-spin" /> Loading...
              </div>
            )}
            {!loading && attacks.length === 0 && (
              <div className="text-center text-gray-500 py-12 text-sm">
                <Database size={32} className="mx-auto mb-3 opacity-30" />
                No attacks found.<br />
                <button onClick={seedStatic} className="text-brand-500 hover:text-brand-600 mt-1">
                  Seed the library →
                </button>
              </div>
            )}
            {attacks.map((a) => (
              <AttackCard
                key={a.id}
                attack={a}
                selected={selected?.id === a.id}
                onClick={() => setSelected(a)}
              />
            ))}
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
