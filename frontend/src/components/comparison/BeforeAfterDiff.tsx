interface Props {
  originalIsr: number
  hardenedIsr: number
  improvementPct: number
  strategy: string
}

export default function BeforeAfterDiff({ originalIsr, hardenedIsr, improvementPct, strategy }: Props) {
  const isImproved = improvementPct > 0

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="card border-red-900/50">
        <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Before Mitigation</div>
        <div className="text-4xl font-bold text-red-400">{(originalIsr * 100).toFixed(1)}%</div>
        <div className="text-gray-500 text-sm mt-1">Injection Success Rate</div>
      </div>

      <div className="card border-brand-500/30 flex flex-col items-center justify-center">
        <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">Improvement</div>
        <div className={`text-4xl font-bold ${isImproved ? 'text-green-400' : 'text-red-400'}`}>
          {isImproved ? '↓' : '↑'} {Math.abs(improvementPct).toFixed(1)}%
        </div>
        <div className="text-gray-500 text-sm mt-1">Strategy: {strategy}</div>
      </div>

      <div className="card border-green-900/50">
        <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">After Mitigation</div>
        <div className="text-4xl font-bold text-green-400">{(hardenedIsr * 100).toFixed(1)}%</div>
        <div className="text-gray-500 text-sm mt-1">Injection Success Rate</div>
      </div>
    </div>
  )
}
