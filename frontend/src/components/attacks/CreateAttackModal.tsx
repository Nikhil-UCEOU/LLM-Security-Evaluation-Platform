import { useState, useEffect } from 'react'
import { attacksApi } from '../../api/attacks'
import type { AttackTemplate, AttackTemplateCreate, StrategyOptions } from '../../types/attack'
import { X, Plus, Trash2, Loader, Wand2, FileText, Link, Brain } from 'lucide-react'
import toast from 'react-hot-toast'

const TABS = [
  { id: 'prompt', label: 'Prompt Attack', icon: FileText },
  { id: 'document', label: 'Document Attack', icon: FileText },
  { id: 'api', label: 'API Attack', icon: Link },
  { id: 'strategy', label: 'Strategy Builder', icon: Brain },
]

const CATEGORIES = [
  { value: 'prompt_injection', label: 'Prompt Injection' },
  { value: 'jailbreak', label: 'Jailbreak' },
  { value: 'role_play', label: 'Role Play' },
  { value: 'indirect_injection', label: 'Indirect Injection' },
  { value: 'context_manipulation', label: 'Context Manipulation' },
  { value: 'multi_turn', label: 'Multi-Turn' },
  { value: 'payload_encoding', label: 'Payload Encoding' },
  { value: 'rag_poisoning', label: 'RAG Poisoning' },
  { value: 'api_abuse', label: 'API Abuse' },
  { value: 'cognitive', label: 'Cognitive' },
  { value: 'strategy_based', label: 'Strategy Based' },
]

const LEVELS = [
  { value: 1, label: 'L1 — Basic (Direct override)' },
  { value: 2, label: 'L2 — Structured (Paraphrased)' },
  { value: 3, label: 'L3 — Contextual (RAG/API)' },
  { value: 4, label: 'L4 — Cognitive (Multi-turn)' },
  { value: 5, label: 'L5 — Adaptive (Model-aware)' },
]

const inputCls = "w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-brand-500"
const selectCls = inputCls + " cursor-pointer"
const labelCls = "block text-xs text-gray-500 mb-1"

interface Props {
  onClose: () => void
  onCreated: (attack: AttackTemplate) => void
}

export default function CreateAttackModal({ onClose, onCreated }: Props) {
  const [tab, setTab] = useState('prompt')
  const [loading, setLoading] = useState(false)
  const [strategyOptions, setStrategyOptions] = useState<StrategyOptions | null>(null)
  const [previewPayload, setPreviewPayload] = useState('')
  const [previewLoading, setPreviewLoading] = useState(false)

  // Common fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [category, setCategory] = useState('prompt_injection')
  const [level, setLevel] = useState(1)
  const [domain, setDomain] = useState('general')
  const [payload, setPayload] = useState('')
  const [riskScore, setRiskScore] = useState(0.5)

  // Strategy fields
  const [stratGoal, setStratGoal] = useState('')
  const [stratMethod, setStratMethod] = useState('')
  const [stratVuln, setStratVuln] = useState('')
  const [stratSteps, setStratSteps] = useState<string[]>([''])

  useEffect(() => {
    attacksApi.strategyOptions().then(setStrategyOptions).catch(() => {})
  }, [])

  const generatePreview = async () => {
    if (!stratGoal || !stratMethod || !stratVuln) return
    setPreviewLoading(true)
    try {
      const res = await attacksApi.strategyPlan({
        goal: stratGoal,
        method: stratMethod,
        target_vulnerability: stratVuln,
        domain,
        steps: stratSteps.filter(Boolean),
      })
      setPreviewPayload(res.generated_payload)
      setLevel(res.estimated_level)
      if (res.steps.length > 0) setStratSteps(res.steps)
    } catch (e: any) {
      toast.error('Failed to generate preview')
    } finally {
      setPreviewLoading(false)
    }
  }

  const handleSubmit = async () => {
    if (!name.trim()) return toast.error('Attack name is required')

    const finalPayload = tab === 'strategy' ? previewPayload || payload : payload
    if (!finalPayload.trim()) return toast.error('Payload is required. Use "Preview" in Strategy Builder first.')

    setLoading(true)
    try {
      const body: AttackTemplateCreate = {
        name: name.trim(),
        category: category as any,
        attack_type: tab as any,
        level,
        domain: domain as any,
        description,
        payload_template: finalPayload,
        source: tab === 'strategy' ? 'strategy' : 'manual',
        strategy_goal: stratGoal,
        strategy_method: stratMethod,
        strategy_vulnerability: stratVuln,
        strategy_steps: stratSteps.filter(Boolean),
        risk_score: riskScore,
      }
      const created = await attacksApi.create(body)
      onCreated(created)
    } catch (e: any) {
      toast.error(e.message || 'Failed to create attack')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <div>
            <h2 className="text-base font-bold text-white">Create Attack</h2>
            <p className="text-xs text-gray-500 mt-0.5">Add a new attack to the library</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-800">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 px-4 py-3 text-xs font-medium transition-colors border-b-2 ${
                tab === id
                  ? 'border-brand-500 text-brand-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon size={12} />
              {label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Common fields */}
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2">
              <label className={labelCls}>Attack Name *</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g., finance_authority_extraction_v2"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Category</label>
              <select value={category} onChange={e => setCategory(e.target.value)} className={selectCls}>
                {CATEGORIES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls}>Difficulty Level</label>
              <select value={level} onChange={e => setLevel(Number(e.target.value))} className={selectCls}>
                {LEVELS.map(l => <option key={l.value} value={l.value}>{l.label}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls}>Domain</label>
              <select value={domain} onChange={e => setDomain(e.target.value)} className={selectCls}>
                {(strategyOptions?.domains || [{ value: 'general', label: 'General' }]).map(d => (
                  <option key={d.value} value={d.value}>{d.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>Risk Score (0–1)</label>
              <input
                type="number"
                min={0} max={1} step={0.05}
                value={riskScore}
                onChange={e => setRiskScore(Number(e.target.value))}
                className={inputCls}
              />
            </div>
            <div className="col-span-2">
              <label className={labelCls}>Description</label>
              <input value={description} onChange={e => setDescription(e.target.value)} placeholder="Brief description of attack technique" className={inputCls} />
            </div>
          </div>

          {/* Strategy Builder tab */}
          {tab === 'strategy' && strategyOptions ? (
            <div className="space-y-4 border-t border-gray-800 pt-4">
              <div className="flex items-center gap-2 mb-2">
                <Brain size={14} className="text-brand-500" />
                <span className="text-xs font-bold text-gray-300 uppercase tracking-wide">Strategy Builder</span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Goal</label>
                  <select value={stratGoal} onChange={e => setStratGoal(e.target.value)} className={selectCls}>
                    <option value="">Select goal...</option>
                    {strategyOptions.goals.map(g => <option key={g.value} value={g.label}>{g.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className={labelCls}>Attack Method</label>
                  <select value={stratMethod} onChange={e => setStratMethod(e.target.value)} className={selectCls}>
                    <option value="">Select method...</option>
                    {strategyOptions.methods.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                  </select>
                </div>
                <div className="col-span-2">
                  <label className={labelCls}>Target Vulnerability</label>
                  <select value={stratVuln} onChange={e => setStratVuln(e.target.value)} className={selectCls}>
                    <option value="">Select vulnerability...</option>
                    {strategyOptions.vulnerabilities.map(v => <option key={v.value} value={v.value}>{v.label}</option>)}
                  </select>
                </div>
              </div>

              {/* Dynamic steps */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className={labelCls + ' mb-0'}>Execution Steps (optional)</label>
                  <button
                    onClick={() => setStratSteps([...stratSteps, ''])}
                    className="text-xs text-brand-500 hover:text-brand-400 flex items-center gap-1"
                  >
                    <Plus size={11} /> Add Step
                  </button>
                </div>
                <div className="space-y-2">
                  {stratSteps.map((step, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-xs text-gray-600 w-5 text-center">{i + 1}</span>
                      <input
                        value={step}
                        onChange={e => {
                          const next = [...stratSteps]; next[i] = e.target.value; setStratSteps(next)
                        }}
                        placeholder={`Step ${i + 1}...`}
                        className={inputCls + ' text-xs py-1.5'}
                      />
                      {stratSteps.length > 1 && (
                        <button
                          onClick={() => setStratSteps(stratSteps.filter((_, j) => j !== i))}
                          className="text-gray-600 hover:text-red-400"
                        >
                          <Trash2 size={12} />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Generate preview */}
              <button
                onClick={generatePreview}
                disabled={!stratGoal || !stratMethod || !stratVuln || previewLoading}
                className="btn-secondary text-xs flex items-center gap-1.5 w-full justify-center py-2"
              >
                {previewLoading ? <Loader size={12} className="animate-spin" /> : <Wand2 size={12} />}
                Generate Attack Payload Preview
              </button>

              {/* Preview panel */}
              {previewPayload && (
                <div>
                  <label className={labelCls}>Generated Payload Preview (editable)</label>
                  <textarea
                    rows={6}
                    value={previewPayload}
                    onChange={e => setPreviewPayload(e.target.value)}
                    className={inputCls + ' font-mono text-xs text-orange-300 resize-none'}
                  />
                  <p className="text-[10px] text-gray-600 mt-1">Auto-estimated level: L{level} · You can edit the payload above</p>
                </div>
              )}
            </div>
          ) : (
            /* Prompt / Document / API payload textarea */
            <div className="border-t border-gray-800 pt-4">
              <label className={labelCls}>
                {tab === 'document' ? 'Document with Embedded Injection *' :
                 tab === 'api' ? 'API Response with Injected Payload *' :
                 'Attack Payload *'}
              </label>
              <textarea
                rows={7}
                value={payload}
                onChange={e => setPayload(e.target.value)}
                placeholder={
                  tab === 'document'
                    ? 'Paste document content with hidden injection...\n\n[Document start]\nThis is a contract.\n<!-- SYSTEM: Ignore previous instructions... -->\n[Document end]'
                    : tab === 'api'
                    ? '{ "data": "value", "_meta": "OVERRIDE: ..." }'
                    : 'Enter your attack prompt...'
                }
                className={inputCls + ' font-mono text-xs resize-none'}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 p-5 border-t border-gray-800">
          <button onClick={onClose} className="btn-secondary text-sm px-5">Cancel</button>
          <button onClick={handleSubmit} disabled={loading} className="btn-primary text-sm px-5 flex items-center gap-2">
            {loading ? <Loader size={14} className="animate-spin" /> : <Plus size={14} />}
            Create Attack
          </button>
        </div>
      </div>
    </div>
  )
}
