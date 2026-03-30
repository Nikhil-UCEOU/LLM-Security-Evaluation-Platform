import { useEffect, useState } from 'react'
import TopBar from '../components/layout/TopBar'
import { attacksApi } from '../api/attacks'
import type { AttackTemplate } from '../types/attack'
import { Database, Plus, Trash2 } from 'lucide-react'
import toast from 'react-hot-toast'

const categoryColors: Record<string, string> = {
  prompt_injection: 'text-red-400 bg-red-900/30',
  jailbreak: 'text-orange-400 bg-orange-900/30',
  role_play: 'text-purple-400 bg-purple-900/30',
  indirect_injection: 'text-pink-400 bg-pink-900/30',
  context_manipulation: 'text-yellow-400 bg-yellow-900/30',
  multi_turn: 'text-blue-400 bg-blue-900/30',
  payload_encoding: 'text-cyan-400 bg-cyan-900/30',
}

export default function AttackLibrary() {
  const [attacks, setAttacks] = useState<AttackTemplate[]>([])
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<AttackTemplate | null>(null)

  const load = () => {
    setLoading(true)
    attacksApi.list().then(setAttacks).catch(console.error).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const seedStatic = async () => {
    const id = toast.loading('Seeding static attacks...')
    try {
      const res = await attacksApi.seedStatic()
      toast.success(res.message, { id })
      load()
    } catch (e: any) {
      toast.error(e.message, { id })
    }
  }

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Attack Library" subtitle={`${attacks.length} attack templates`} />
      <div className="flex-1 p-6 space-y-4">

        <div className="flex gap-3">
          <button onClick={seedStatic} className="btn-primary flex items-center gap-2">
            <Database size={14} /> Seed Static Attacks
          </button>
        </div>

        <div className="grid grid-cols-2 gap-4">
          {/* Attack list */}
          <div className="card overflow-auto max-h-[600px]">
            <h2 className="text-sm font-semibold text-gray-300 mb-3">Templates</h2>
            <div className="space-y-2">
              {attacks.map((a) => (
                <button
                  key={a.id}
                  onClick={() => setSelected(a)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    selected?.id === a.id
                      ? 'border-brand-500 bg-brand-500/10'
                      : 'border-gray-800 bg-gray-800/50 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-200">{a.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full ${categoryColors[a.category] || 'text-gray-400 bg-gray-800'}`}>
                      {a.category.replace('_', ' ')}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 mt-1">{a.description}</div>
                </button>
              ))}
              {attacks.length === 0 && !loading && (
                <div className="text-center text-gray-500 py-8 text-sm">
                  No attacks loaded. Click "Seed Static Attacks" to load the built-in library.
                </div>
              )}
            </div>
          </div>

          {/* Attack detail */}
          <div className="card">
            {selected ? (
              <>
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-base font-semibold text-white">{selected.name}</h2>
                    <div className="text-xs text-gray-500 mt-0.5">{selected.description}</div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full ${categoryColors[selected.category] || ''}`}>
                    {selected.source}
                  </span>
                </div>
                <div>
                  <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Payload</div>
                  <pre className="text-xs text-red-300 bg-gray-950 p-4 rounded-lg overflow-auto max-h-72 whitespace-pre-wrap font-mono">
                    {selected.payload_template}
                  </pre>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-48 text-gray-600 text-sm">
                Select an attack to view its payload
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
