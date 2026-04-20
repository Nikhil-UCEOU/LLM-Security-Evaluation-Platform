import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Dashboard from './pages/Dashboard'
import EvaluationRun from './pages/EvaluationRun'
import AttackLibrary from './pages/AttackLibrary'
import Results from './pages/Results'
import Mitigation from './pages/Mitigation'
import Settings from './pages/Settings'
import Benchmark from './pages/Benchmark'
import RiskDashboard from './pages/RiskDashboard'

export default function App() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 flex flex-col min-h-screen overflow-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/run" element={<EvaluationRun />} />
          <Route path="/attacks" element={<AttackLibrary />} />
          <Route path="/benchmark" element={<Benchmark />} />
          <Route path="/results" element={<Results />} />
          <Route path="/results/:runId" element={<Results />} />
          <Route path="/mitigation" element={<Mitigation />} />
          <Route path="/mitigation/:runId" element={<Mitigation />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/risk" element={<RiskDashboard />} />
        </Routes>
      </main>
    </div>
  )
}
