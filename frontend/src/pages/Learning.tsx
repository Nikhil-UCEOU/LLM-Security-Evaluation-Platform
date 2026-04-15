import { useEffect, useState } from 'react'
import TopBar from '../components/layout/TopBar'
import client from '../api/client'
import {
  Brain, TrendingUp, Target, Zap, RefreshCw,
  ChevronRight, BarChart3, Activity,
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from 'recharts'

const ALL_PROVIDERS = [
  { id: 'openai',    label: 'OpenAI',          models: ['gpt-4o-mini', 'gpt-4o', 'gpt-3.5-turbo'] },
  { id: 'anthropic', label: 'Anthropic',       models: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001'] },
  { id: 'ollama',    label: 'Ollama (Local)',   models: ['llama3', 'mistral', 'phi', 'tinyllama', 'gemma:2b'] },
]

const CATEGORY_COLORS: Record<string, string> = {
  prompt_injection:    '#e8003d',
  jailbreak:           '#f97316',
  role_play:           '#eab308',
  indirect_injection:  '#6366f1',
  context_manipulation:'#8b5cf6',
  multi_turn:          '#ec4899',
  payload_encoding:    '#3b82f6',
  rag_poisoning:       '#10b981',
  api_abuse:           '#f59e0b',
  cognitive:           '#06b6d4',
  strategy_based:      '#84cc16',
}

export default function Learning() {
  const [insights, setInsights] = useState<any>(null)
  const [provider, setProvider] = useState('openai')
  const [model, setModel] = useState('gpt-4o-mini')
  const [loading, setLoading] = useState(false)

  const availableModels = ALL_PROVIDERS.find(p => p.id === provider)?.models || []

  useEffect(() => {
    setLoading(true)
    client.get('/learning/insights', { params: { provider, model } })
      .then(r => setInsights(r.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [provider, model])

  const topAttacks: any[] = insights?.top_attacks || []
  const vulnCats: string[] = insights?.most_vulnerable_categories || []

  // Chart data for top attacks
  const barData = topAttacks.slice(0, 10).map((a: any) => ({
    name: (a.attack_name || a.attack_id || '').slice(0, 22),
    rate: Math.round((a.success_rate || 0) * 100),
    category: a.category || 'unknown',
  }))

  // Radar data for category vulnerability
  const radarData = vulnCats.slice(0, 8).map((cat: string) => ({
    category: cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()).slice(0, 14),
    value: topAttacks.filter((a: any) => a.category === cat).reduce((s: number, a: any) => s + (a.success_rate || 0), 0) / Math.max(topAttacks.filter((a: any) => a.category === cat).length, 1) * 100,
  }))

  const hasData = topAttacks.length > 0

  return (
    <div className="flex-1 flex flex-col overflow-y-auto">
      <TopBar title="Intelligence Engine" subtitle="What CortexFlow has learned from all evaluations" />

      <div className="flex-1 p-6 space-y-6 max-w-6xl mx-auto w-full">

        {/* Filter row */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <select value={provider} onChange={e => { setProvider(e.target.value); setModel(ALL_PROVIDERS.find(p => p.id === e.target.value)?.models[0] || '') }}
              className="text-sm px-3 py-2 rounded-xl border outline-none"
              style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
              {ALL_PROVIDERS.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <select value={model} onChange={e => setModel(e.target.value)}
              className="text-sm px-3 py-2 rounded-xl border outline-none"
              style={{ background: '#141625', borderColor: 'rgba(255,255,255,0.1)', color: '#e2e8f0' }}>
              {availableModels.map(m => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
          <button onClick={() => {
            setLoading(true)
            client.get('/learning/insights', { params: { provider, model } })
              .then(r => setInsights(r.data))
              .catch(console.error)
              .finally(() => setLoading(false))
          }}
            className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors px-3 py-2 rounded-xl border"
            style={{ borderColor: 'rgba(255,255,255,0.08)' }}>
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>

        {/* Empty state */}
        {!loading && !hasData && (
          <div className="text-center py-20">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
              style={{ background: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.2)' }}>
              <Brain size={24} style={{ color: '#6366f1' }} />
            </div>
            <h3 className="text-lg font-bold text-white mb-2">No learning data yet</h3>
            <p className="text-sm text-gray-500 mb-4">
              Run evaluations against {provider}/{model} to build the intelligence database.
            </p>
            <a href="/run" className="text-pink-400 text-sm flex items-center gap-1 justify-center hover:text-pink-300 transition-colors">
              Start evaluation <ChevronRight size={12} />
            </a>
          </div>
        )}

        {hasData && (
          <>
            {/* Summary stats */}
            <div className="grid grid-cols-3 gap-4">
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(232,0,61,0.07)', borderColor: 'rgba(232,0,61,0.2)' }}>
                <div className="flex items-center gap-2 mb-3">
                  <Activity size={14} style={{ color: '#e8003d' }} />
                  <span className="text-xs text-gray-400 font-medium">Attack Patterns Found</span>
                </div>
                <div className="text-3xl font-black text-white">{topAttacks.length}</div>
                <div className="text-xs text-gray-600 mt-1">unique attack types tracked</div>
              </div>
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(245,158,11,0.07)', borderColor: 'rgba(245,158,11,0.2)' }}>
                <div className="flex items-center gap-2 mb-3">
                  <TrendingUp size={14} style={{ color: '#f59e0b' }} />
                  <span className="text-xs text-gray-400 font-medium">Most Vulnerable Areas</span>
                </div>
                <div className="text-3xl font-black text-white">{vulnCats.length}</div>
                <div className="text-xs text-gray-600 mt-1">categories with high attack rate</div>
              </div>
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(99,102,241,0.07)', borderColor: 'rgba(99,102,241,0.2)' }}>
                <div className="flex items-center gap-2 mb-3">
                  <Zap size={14} style={{ color: '#6366f1' }} />
                  <span className="text-xs text-gray-400 font-medium">Top Attack Success Rate</span>
                </div>
                <div className="text-3xl font-black text-white">
                  {topAttacks.length > 0 ? `${(Math.max(...topAttacks.map((a: any) => a.success_rate || 0)) * 100).toFixed(0)}%` : '—'}
                </div>
                <div className="text-xs text-gray-600 mt-1">best performing attack</div>
              </div>
            </div>

            {/* Vulnerable categories */}
            {vulnCats.length > 0 && (
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-2 mb-4">
                  <Target size={14} className="text-red-400" />
                  <h2 className="text-sm font-semibold text-gray-300">Most Vulnerable Attack Categories</h2>
                </div>
                <div className="flex flex-wrap gap-2">
                  {vulnCats.map((cat: string) => (
                    <span key={cat} className="text-xs font-medium px-3 py-1.5 rounded-full border"
                      style={{
                        background: `${CATEGORY_COLORS[cat] || '#e8003d'}15`,
                        borderColor: `${CATEGORY_COLORS[cat] || '#e8003d'}40`,
                        color: CATEGORY_COLORS[cat] || '#e8003d',
                      }}>
                      {cat.replace(/_/g, ' ')}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Charts row */}
            <div className="grid grid-cols-2 gap-5">
              {/* Top attacks bar chart */}
              <div className="rounded-2xl border p-5"
                style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                <div className="flex items-center gap-2 mb-4">
                  <BarChart3 size={14} className="text-pink-400" />
                  <h3 className="text-sm font-semibold text-gray-300">Top Attacks by Success Rate</h3>
                </div>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={barData} layout="vertical" margin={{ left: 4, right: 16 }}>
                    <XAxis type="number" domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 10 }} tickFormatter={v => `${v}%`} />
                    <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 9 }} width={110} />
                    <Tooltip
                      formatter={(v: any) => [`${v}%`, 'Success Rate']}
                      contentStyle={{ background: '#141625', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12 }}
                    />
                    <Bar dataKey="rate" radius={3} maxBarSize={14}>
                      {barData.map((d, i) => (
                        <Cell key={i} fill={CATEGORY_COLORS[d.category] || '#e8003d'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Radar chart for category coverage */}
              {radarData.length >= 3 && (
                <div className="rounded-2xl border p-5"
                  style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
                  <div className="flex items-center gap-2 mb-4">
                    <Target size={14} className="text-indigo-400" />
                    <h3 className="text-sm font-semibold text-gray-300">Vulnerability Profile</h3>
                  </div>
                  <ResponsiveContainer width="100%" height={220}>
                    <RadarChart data={radarData} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                      <PolarGrid stroke="rgba(255,255,255,0.05)" />
                      <PolarAngleAxis dataKey="category" tick={{ fill: '#6b7280', fontSize: 9 }} />
                      <Radar dataKey="value" stroke="#e8003d" fill="#e8003d" fillOpacity={0.15} dot={{ fill: '#e8003d', r: 2 }} />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Full table */}
            <div className="rounded-2xl border"
              style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
              <div className="flex items-center gap-2 p-5">
                <Brain size={14} className="text-indigo-400" />
                <h3 className="text-sm font-semibold text-gray-300">All Tracked Attack Patterns</h3>
              </div>
              <div className="overflow-x-auto px-5 pb-5">
                <table className="w-full text-sm">
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.07)' }}>
                      <th className="pb-3 pr-4 text-left text-xs font-medium text-gray-500">Attack Pattern</th>
                      <th className="pb-3 pr-4 text-left text-xs font-medium text-gray-500">Category</th>
                      <th className="pb-3 pr-4 text-left text-xs font-medium text-gray-500">Success Rate</th>
                      <th className="pb-3 text-left text-xs font-medium text-gray-500">Intelligence Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topAttacks.map((a: any) => (
                      <tr key={a.attack_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                        className="hover:bg-white/02 transition-colors">
                        <td className="py-3 pr-4 font-medium text-gray-200">{a.attack_name || a.attack_id}</td>
                        <td className="py-3 pr-4">
                          <span className="text-xs px-2 py-0.5 rounded-full"
                            style={{
                              background: `${CATEGORY_COLORS[a.category] || '#e8003d'}15`,
                              color: CATEGORY_COLORS[a.category] || '#e8003d',
                            }}>
                            {(a.category || 'unknown').replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 pr-4">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 max-w-24 h-1.5 rounded-full bg-white/05 overflow-hidden">
                              <div className="h-full rounded-full transition-all"
                                style={{ width: `${(a.success_rate || 0) * 100}%`, background: CATEGORY_COLORS[a.category] || '#e8003d' }} />
                            </div>
                            <span className="text-gray-400 text-xs w-10">{((a.success_rate || 0) * 100).toFixed(0)}%</span>
                          </div>
                        </td>
                        <td className="py-3">
                          <span style={{ color: '#6366f1' }} className="font-mono text-sm">{(a.rank_score || 0).toFixed(2)}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
