import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import TopBar from '../components/layout/TopBar'
import BeforeAfterDiff from '../components/comparison/BeforeAfterDiff'
import client from '../api/client'

export default function Mitigation() {
  const { runId } = useParams<{ runId?: string }>()
  const [data, setData] = useState<any>(null)

  useEffect(() => {
    if (!runId) return
    client.get(`/mitigations/${runId}`).then((r) => setData(r.data)).catch(console.error)
  }, [runId])

  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Mitigation" subtitle="Before vs After hardening comparison" />
      <div className="flex-1 p-6 space-y-6">
        {!runId && (
          <p className="text-gray-500 text-sm">Navigate from a Results page to view mitigation details.</p>
        )}
        {data && (
          <>
            <BeforeAfterDiff
              originalIsr={data.result?.original_isr || 0}
              hardenedIsr={data.result?.hardened_isr || 0}
              improvementPct={data.result?.improvement_pct || 0}
              strategy={data.plan?.strategy || 'auto'}
            />

            <div className="grid grid-cols-2 gap-6">
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-3">Original System Prompt</div>
                <pre className="text-xs text-gray-400 bg-gray-950 p-4 rounded-lg overflow-auto max-h-64 whitespace-pre-wrap font-mono">
                  {data.plan?.original_system_prompt || 'N/A'}
                </pre>
              </div>
              <div className="card border-green-900/30">
                <div className="text-xs text-green-500 uppercase tracking-wide mb-3">Hardened System Prompt</div>
                <pre className="text-xs text-green-300 bg-gray-950 p-4 rounded-lg overflow-auto max-h-64 whitespace-pre-wrap font-mono">
                  {data.plan?.hardened_prompt || 'N/A'}
                </pre>
              </div>
            </div>

            {data.plan?.guardrails?.length > 0 && (
              <div className="card">
                <div className="text-xs text-gray-500 uppercase tracking-wide mb-3">Guardrails Applied</div>
                <div className="space-y-2">
                  {data.plan.guardrails.map((g: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 p-3 bg-gray-800 rounded-lg">
                      <span className="text-xs bg-brand-500/20 text-brand-500 px-2 py-0.5 rounded-full">{g.type}</span>
                      <div>
                        <div className="text-xs font-medium text-gray-300">{g.target}</div>
                        <div className="text-xs text-gray-500">{g.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
