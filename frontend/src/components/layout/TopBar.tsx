import { Bell, Activity } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
}

export default function TopBar({ title, subtitle }: TopBarProps) {
  return (
    <header className="h-14 flex items-center justify-between px-6 flex-shrink-0"
      style={{
        background: 'rgba(8,13,26,0.95)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(8px)',
      }}>
      <div>
        <h1 className="text-white font-bold text-base leading-tight tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs mt-0.5" style={{ color: 'rgba(255,255,255,0.35)' }}>{subtitle}</p>}
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full"
          style={{ background: 'rgba(34,197,94,0.1)', color: '#22c55e', border: '1px solid rgba(34,197,94,0.2)' }}>
          <Activity size={11} />
          <span>API Connected</span>
        </div>
        <button className="text-gray-600 hover:text-gray-300 transition-colors p-1.5 rounded-lg hover:bg-gray-800">
          <Bell size={16} />
        </button>
      </div>
    </header>
  )
}
