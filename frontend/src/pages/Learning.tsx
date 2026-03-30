import { useEffect, useState } from 'react'
import TopBar from '../components/layout/TopBar'
import client from '../api/client'
import { Brain, TrendingUp } from 'lucide-react'

export default function Learning() {
  const [insights, setInsights] = useState<any>(null)
  const [provider, setProvider] = useState('openai')
  const [model, setModel] = useState('gpt-4o-mini')

  useEffect(() => {
    client.get('/learning/insights', { params: { provider, model } })
      .then((r) => setInsights(r.data))
      .catch(console.error)
  }, [provider, model])

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Learning Engine" subtitle="Historical attack effectiveness and trends" />
      <div className="flex-1 p-6 space-y-6">

        <div className="flex gap-4 items-end">
          <div>
            <label className="block text-xs text-gray-500 mb-1">Provider</label>
            <input
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Model</label>
            <input
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500"
            />
          </div>
        </div>

        {insights?.most_vulnerable_categories?.length > 0 && (
          <div className="card">
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp size={16} className="text-red-400" />
              <h2 className="text-sm font-semibold text-gray-300">Most Vulnerable Categories</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              {insights.most_vulnerable_categories.map((cat: string) => (
                <span key={cat} className="badge-unsafe">{cat.replace('_', ' ')}</span>
              ))}
            </div>
          </div>
        )}

        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Brain size={16} className="text-brand-500" />
            <h2 className="text-sm font-semibold text-gray-300">Top Attacks by Success Rate</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">Attack</th>
                  <th className="pb-3 pr-4 font-medium">Category</th>
                  <th className="pb-3 pr-4 font-medium">Success Rate</th>
                  <th className="pb-3 font-medium">Rank Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {insights?.top_attacks?.map((a: any) => (
                  <tr key={a.attack_id} className="hover:bg-gray-800/50">
                    <td className="py-3 pr-4 font-medium text-gray-200">{a.attack_name}</td>
                    <td className="py-3 pr-4 text-gray-400">{a.category}</td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                          <div
                            className="h-1.5 rounded-full bg-red-500"
                            style={{ width: `${a.success_rate * 100}%` }}
                          />
                        </div>
                        <span className="text-gray-400 w-10 text-right">{(a.success_rate * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="py-3 text-brand-500">{a.rank_score.toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(!insights?.top_attacks || insights.top_attacks.length === 0) && (
              <div className="text-center text-gray-500 py-8 text-sm">
                No learning data yet. Run evaluations to build the knowledge base.
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  )
}
