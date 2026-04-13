import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Zap, Shield, BookOpen, GitBranch,
  Settings, Brain, ChevronRight, FlaskConical, BarChart3,
} from 'lucide-react'
import clsx from 'clsx'

const nav = [
  { to: '/',          icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/run',       icon: Zap,             label: 'Evaluation Lab' },
  { to: '/attacks',   icon: BookOpen,         label: 'Attack Library' },
  { to: '/benchmark', icon: BarChart3,        label: 'Benchmark',  accent: true },
  { to: '/results',   icon: GitBranch,        label: 'Results' },
  { to: '/mitigation',icon: Shield,           label: 'Mitigation Lab' },
  { to: '/learning',  icon: Brain,            label: 'Learning' },
  { to: '/settings',  icon: Settings,         label: 'Settings' },
]

export default function Sidebar() {
  return (
    <aside className="w-56 min-h-screen flex flex-col" style={{
      background: 'linear-gradient(180deg, #080d1a 0%, #050a14 100%)',
      borderRight: '1px solid rgba(255,255,255,0.06)',
    }}>
      {/* Logo */}
      <div className="p-5 pb-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'linear-gradient(135deg, #e8003d 0%, #4f6ef7 100%)', boxShadow: '0 0 16px rgba(232,0,61,0.35)' }}>
            <Brain size={16} className="text-white" />
          </div>
          <div>
            <div className="font-bold text-white text-xs leading-tight tracking-wide">CortexFlow AI</div>
            <div className="text-[10px] mt-0.5" style={{ color: 'rgba(255,255,255,0.3)' }}>Security Platform</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-0.5">
        {nav.map(({ to, icon: Icon, label, accent }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-all group relative',
                isActive
                  ? accent
                    ? 'text-white'
                    : 'text-white'
                  : 'text-gray-500 hover:text-gray-200'
              )
            }
            style={({ isActive }) => isActive ? {
              background: accent
                ? 'linear-gradient(90deg, rgba(232,0,61,0.18) 0%, rgba(79,110,247,0.12) 100%)'
                : 'rgba(79,110,247,0.12)',
              borderLeft: `2px solid ${accent ? '#e8003d' : '#4f6ef7'}`,
            } : { borderLeft: '2px solid transparent' }}
          >
            <Icon size={15} className={clsx(
              'flex-shrink-0',
              accent ? 'text-accent-red' : 'text-current'
            )} />
            <span className="flex-1">{label}</span>
            {accent && (
              <span className="text-[9px] font-bold px-1 py-0.5 rounded"
                style={{ background: 'rgba(232,0,61,0.2)', color: '#e8003d' }}>
                NEW
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Version */}
      <div className="p-4" style={{ borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="text-[10px] text-center" style={{ color: 'rgba(255,255,255,0.2)' }}>
          v2.0 · Enterprise Edition
        </div>
      </div>
    </aside>
  )
}
