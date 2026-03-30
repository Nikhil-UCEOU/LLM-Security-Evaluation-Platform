import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'

interface Props {
  data: { category: string; isr: number }[]
}

const getColor = (isr: number) => {
  if (isr >= 0.7) return '#ef4444'
  if (isr >= 0.4) return '#f97316'
  if (isr >= 0.2) return '#eab308'
  return '#22c55e'
}

export default function RiskScoreChart({ data }: Props) {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-gray-500 text-sm">
        No data yet. Run an evaluation first.
      </div>
    )
  }

  const chartData = data.map((d) => ({
    category: d.category.replace('_', ' '),
    isr: Math.round(d.isr * 100),
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
        <XAxis dataKey="category" tick={{ fontSize: 11, fill: '#9ca3af' }} />
        <YAxis tick={{ fontSize: 11, fill: '#9ca3af' }} unit="%" domain={[0, 100]} />
        <Tooltip
          contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
          formatter={(v: number) => [`${v}%`, 'ISR']}
        />
        <Bar dataKey="isr" radius={[4, 4, 0, 0]}>
          {chartData.map((entry, i) => (
            <Cell key={i} fill={getColor(entry.isr / 100)} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
