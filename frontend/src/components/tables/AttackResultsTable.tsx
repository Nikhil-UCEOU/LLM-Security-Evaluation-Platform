import { useState } from 'react'
import type { EvaluationResult } from '../../types/evaluation'
import clsx from 'clsx'
import { ChevronDown, ChevronUp } from 'lucide-react'

interface Props {
  results: EvaluationResult[]
}

export default function AttackResultsTable({ results }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null)

  const severityBadge = (s: string) => {
    const map: Record<string, string> = {
      critical: 'badge-critical',
      high: 'badge-high',
      medium: 'badge-medium',
      low: 'badge-low',
      none: 'badge-safe',
    }
    return <span className={map[s] || 'badge-low'}>{s}</span>
  }

  const classificationBadge = (c: string) => {
    const map: Record<string, string> = {
      safe: 'badge-safe',
      unsafe: 'badge-unsafe',
      partial: 'badge-medium',
      unknown: 'badge-low',
    }
    return <span className={map[c] || 'badge-low'}>{c}</span>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-gray-500 border-b border-gray-800">
            <th className="pb-3 pr-4 font-medium">Attack</th>
            <th className="pb-3 pr-4 font-medium">Classification</th>
            <th className="pb-3 pr-4 font-medium">Severity</th>
            <th className="pb-3 pr-4 font-medium">Latency</th>
            <th className="pb-3 font-medium">Details</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {results.map((r) => (
            <>
              <tr key={r.id} className="hover:bg-gray-800/50 transition-colors">
                <td className="py-3 pr-4">
                  <div className="font-medium text-gray-200">{r.attack_name}</div>
                </td>
                <td className="py-3 pr-4">{classificationBadge(r.classification)}</td>
                <td className="py-3 pr-4">{severityBadge(r.severity)}</td>
                <td className="py-3 pr-4 text-gray-400">{r.latency_ms}ms</td>
                <td className="py-3">
                  <button
                    onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                    className="text-brand-500 hover:text-brand-600 flex items-center gap-1"
                  >
                    {expanded === r.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    <span className="text-xs">{expanded === r.id ? 'Hide' : 'View'}</span>
                  </button>
                </td>
              </tr>
              {expanded === r.id && (
                <tr key={`${r.id}-detail`} className="bg-gray-800/30">
                  <td colSpan={5} className="px-4 py-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <div className="text-xs text-gray-500 mb-1 font-semibold uppercase tracking-wide">Attack Payload</div>
                        <pre className="text-xs text-red-300 bg-gray-900 p-3 rounded-lg overflow-auto max-h-32 whitespace-pre-wrap">{r.attack_payload}</pre>
                      </div>
                      <div>
                        <div className="text-xs text-gray-500 mb-1 font-semibold uppercase tracking-wide">Model Response</div>
                        <pre className="text-xs text-gray-300 bg-gray-900 p-3 rounded-lg overflow-auto max-h-32 whitespace-pre-wrap">{r.response_text || 'No response'}</pre>
                      </div>
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
      {results.length === 0 && (
        <div className="text-center text-gray-500 py-12 text-sm">No results found.</div>
      )}
    </div>
  )
}
