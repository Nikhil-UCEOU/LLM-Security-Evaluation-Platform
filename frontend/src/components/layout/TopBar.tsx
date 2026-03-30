import { Bell, Activity } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
}

export default function TopBar({ title, subtitle }: TopBarProps) {
  return (
    <header className="h-16 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-6">
      <div>
        <h1 className="text-white font-semibold text-lg leading-tight">{title}</h1>
        {subtitle && <p className="text-gray-500 text-xs">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-green-400 text-xs">
          <Activity size={14} />
          <span>API Connected</span>
        </div>
        <button className="relative text-gray-400 hover:text-gray-100 transition-colors">
          <Bell size={20} />
        </button>
      </div>
    </header>
  )
}
