import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Zap, Shield, BookOpen, GitBranch,
  Settings, Brain, ChevronRight,
} from 'lucide-react'
import clsx from 'clsx'

const nav = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/run', icon: Zap, label: 'Run Evaluation' },
  { to: '/attacks', icon: BookOpen, label: 'Attack Library' },
  { to: '/results', icon: GitBranch, label: 'Results' },
  { to: '/mitigation', icon: Shield, label: 'Mitigation' },
  { to: '/learning', icon: Brain, label: 'Learning' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="p-6 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-brand-500 flex items-center justify-center">
            <Brain size={20} className="text-white" />
          </div>
          <div>
            <div className="font-bold text-white text-sm leading-tight">CortexFlow AI</div>
            <div className="text-gray-500 text-xs">LLM Security Platform</div>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {nav.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group',
                isActive
                  ? 'bg-brand-500/20 text-brand-500 border border-brand-500/30'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              )
            }
          >
            <Icon size={18} />
            <span className="flex-1">{label}</span>
            <ChevronRight size={14} className="opacity-0 group-hover:opacity-100 transition-opacity" />
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-800">
        <div className="text-xs text-gray-600 text-center">v1.0.0 · Research Edition</div>
      </div>
    </aside>
  )
}
