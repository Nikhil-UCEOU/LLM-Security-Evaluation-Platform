import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useEvaluationStore } from '../store/evaluationStore'
import TopBar from '../components/layout/TopBar'
import toast from 'react-hot-toast'
import { Play, Loader } from 'lucide-react'
import type { EvaluationRunRequest } from '../types/evaluation'
import type { AttackCategory } from '../types/attack'

const ATTACK_CATEGORIES: AttackCategory[] = [
  'prompt_injection', 'jailbreak', 'role_play',
  'indirect_injection', 'context_manipulation', 'payload_encoding',
]

const PROVIDERS = [
  { id: 'openai', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'] },
  { id: 'anthropic', models: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001'] },
  { id: 'ollama', models: ['llama3', 'mistral', 'phi3'] },
]

export default function EvaluationRun() {
  const navigate = useNavigate()
  const { runEvaluation, loading } = useEvaluationStore()

  const [form, setForm] = useState<EvaluationRunRequest>({
    provider: 'openai',
    model: 'gpt-4o-mini',
    system_prompt: 'You are a helpful assistant.',
    attack_categories: [],
    include_adaptive: false,
    max_attacks: 10,
  })

  const selectedProvider = PROVIDERS.find((p) => p.id === form.provider)

  const toggleCategory = (cat: AttackCategory) => {
    setForm((f) => ({
      ...f,
      attack_categories: f.attack_categories.includes(cat)
        ? f.attack_categories.filter((c) => c !== cat)
        : [...f.attack_categories, cat],
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const toastId = toast.loading('Running evaluation pipeline...')
    try {
      const report = await runEvaluation(form)
      toast.success(`Evaluation complete! ISR: ${(report.global_isr * 100).toFixed(1)}%`, { id: toastId })
      navigate(`/results/${report.run_id}`)
    } catch (err: any) {
      toast.error(err.message || 'Evaluation failed', { id: toastId })
    }
  }

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Run Evaluation" subtitle="Configure and launch the full CortexFlow pipeline" />
      <div className="flex-1 p-6">
        <form onSubmit={handleSubmit} className="max-w-2xl space-y-6">

          {/* Provider */}
          <div className="card space-y-4">
            <h2 className="text-sm font-semibold text-gray-300">Target LLM</h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-gray-500 mb-1">Provider</label>
                <select
                  value={form.provider}
                  onChange={(e) => setForm((f) => ({ ...f, provider: e.target.value, model: PROVIDERS.find(p => p.id === e.target.value)?.models[0] || '' }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500"
                >
                  {PROVIDERS.map((p) => (
                    <option key={p.id} value={p.id}>{p.id}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1">Model</label>
                <select
                  value={form.model}
                  onChange={(e) => setForm((f) => ({ ...f, model: e.target.value }))}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500"
                >
                  {selectedProvider?.models.map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* System Prompt */}
          <div className="card">
            <label className="block text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">System Prompt</label>
            <textarea
              rows={4}
              value={form.system_prompt}
              onChange={(e) => setForm((f) => ({ ...f, system_prompt: e.target.value }))}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500 font-mono resize-none"
              placeholder="Enter the system prompt to evaluate..."
            />
          </div>

          {/* Attack Categories */}
          <div className="card">
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Attack Categories</h2>
            <p className="text-xs text-gray-600 mb-3">Leave all unchecked to use all categories.</p>
            <div className="flex flex-wrap gap-2">
              {ATTACK_CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => toggleCategory(cat)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    form.attack_categories.includes(cat)
                      ? 'bg-brand-500 text-white'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {cat.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          {/* Options */}
          <div className="card space-y-4">
            <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Options</h2>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm text-gray-300">Max Attacks</div>
                <div className="text-xs text-gray-600">Number of attack payloads to run</div>
              </div>
              <input
                type="number"
                min={1}
                max={50}
                value={form.max_attacks}
                onChange={(e) => setForm((f) => ({ ...f, max_attacks: parseInt(e.target.value) }))}
                className="w-20 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 text-center focus:outline-none focus:border-brand-500"
              />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm text-gray-300">Adaptive Attacks</div>
                <div className="text-xs text-gray-600">Generate novel attacks via LLM (slower)</div>
              </div>
              <button
                type="button"
                onClick={() => setForm((f) => ({ ...f, include_adaptive: !f.include_adaptive }))}
                className={`w-12 h-6 rounded-full transition-colors ${form.include_adaptive ? 'bg-brand-500' : 'bg-gray-700'}`}
              >
                <div className={`w-5 h-5 bg-white rounded-full mx-0.5 transition-transform ${form.include_adaptive ? 'translate-x-6' : 'translate-x-0'}`} />
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary w-full flex items-center justify-center gap-2 py-3"
          >
            {loading ? <Loader size={16} className="animate-spin" /> : <Play size={16} />}
            {loading ? 'Running Pipeline...' : 'Launch Evaluation'}
          </button>
        </form>
      </div>
    </div>
  )
}
