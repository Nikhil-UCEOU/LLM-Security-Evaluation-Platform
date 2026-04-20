import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Zap, Shield, BookOpen,
  Settings, Brain, BarChart3, GitBranch, ShieldAlert,
} from 'lucide-react'
import clsx from 'clsx'

const nav = [
  { to: '/',           icon: LayoutDashboard, label: 'Dashboard',      step: null },
  { to: '/run',        icon: Zap,             label: 'Evaluation Lab', step: 1 },
  { to: '/results',    icon: GitBranch,        label: 'Results',        step: 2 },
  { to: '/mitigation', icon: Shield,           label: 'Mitigation Lab', step: 3 },
  { to: '/attacks',    icon: BookOpen,          label: 'Attack Library', step: null },
  { to: '/benchmark',  icon: BarChart3,         label: 'Benchmark',      step: null, accent: true },
  { to: '/risk',       icon: ShieldAlert,       label: 'Risk Dashboard', step: null },
  { to: '/settings',   icon: Settings,          label: 'Settings',       step: null },
]

export default function Sidebar() {
  return (
    <aside className="w-52 min-h-screen flex flex-col flex-shrink-0"
      style={{ background: '#0a0d18', borderRight: '1px solid rgba(255,255,255,0.06)' }}>

      {/* Logo */}
      <div className="p-4 pb-3" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: 'linear-gradient(135deg, #e8003d 0%, #6366f1 100%)', boxShadow: '0 0 14px rgba(232,0,61,0.3)' }}>
            <Brain size={14} className="text-white" />
          </div>
          <div>
            <div className="font-bold text-white text-[11px] leading-tight tracking-wide">CortexFlow AI</div>
            <div className="text-[9px] mt-0.5" style={{ color: 'rgba(255,255,255,0.25)' }}>Security Platform</div>
          </div>
        </div>
      </div>

      {/* Workflow label */}
      <div className="px-4 pt-4 pb-1">
        <div className="text-[9px] font-bold uppercase tracking-widest" style={{ color: 'rgba(255,255,255,0.2)' }}>
          Workflow
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 pb-2 space-y-0.5">
        {nav.map(({ to, icon: Icon, label, step, accent }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-2 px-2.5 py-2 rounded-xl text-[11px] font-medium transition-all group relative',
                isActive ? 'text-white' : 'text-gray-500 hover:text-gray-300'
              )
            }
            style={({ isActive }) => isActive ? {
              background: accent
                ? 'linear-gradient(90deg, rgba(232,0,61,0.15) 0%, rgba(99,102,241,0.10) 100%)'
                : 'rgba(255,255,255,0.07)',
              boxShadow: isActive && accent ? '0 0 10px rgba(232,0,61,0.1)' : undefined,
            } : {}}
          >
            <Icon size={13} className="flex-shrink-0" style={
              (() => {
                // will resolve after render
                return {}
              })()
            } />
            <span className="flex-1 truncate">{label}</span>
            {step && (
              <span className="text-[8px] font-bold w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0"
                style={{ background: 'rgba(232,0,61,0.2)', color: '#f87171' }}>
                {step}
              </span>
            )}
            {accent && !step && (
              <span className="text-[8px] font-bold px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(232,0,61,0.15)', color: '#e8003d' }}>
                NEW
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Version */}
      <div className="p-3" style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
        <div className="text-[9px] text-center" style={{ color: 'rgba(255,255,255,0.15)' }}>
          v2.0 · Enterprise Edition
        </div>
      </div>
    </aside>
  )
}
