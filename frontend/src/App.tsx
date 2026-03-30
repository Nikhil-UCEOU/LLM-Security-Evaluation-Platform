import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Dashboard from './pages/Dashboard'
import EvaluationRun from './pages/EvaluationRun'
import AttackLibrary from './pages/AttackLibrary'
import Results from './pages/Results'
import Mitigation from './pages/Mitigation'
import Learning from './pages/Learning'
import Settings from './pages/Settings'

export default function App() {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 flex flex-col min-h-screen overflow-auto">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/run" element={<EvaluationRun />} />
          <Route path="/attacks" element={<AttackLibrary />} />
          <Route path="/results" element={<Results />} />
          <Route path="/results/:runId" element={<Results />} />
          <Route path="/mitigation" element={<Mitigation />} />
          <Route path="/mitigation/:runId" element={<Mitigation />} />
          <Route path="/learning" element={<Learning />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}
