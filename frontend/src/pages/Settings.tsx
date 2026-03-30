import TopBar from '../components/layout/TopBar'

export default function Settings() {
  return (
    <div className="flex-1 flex flex-col">
      <TopBar title="Settings" subtitle="Configure API keys and platform options" />
      <div className="flex-1 p-6 max-w-xl space-y-6">
        <div className="card space-y-4">
          <h2 className="text-sm font-semibold text-gray-300">API Keys</h2>
          <p className="text-xs text-gray-500">
            API keys are configured via the <code className="bg-gray-800 px-1 py-0.5 rounded text-brand-400">.env</code> file on the backend server.
            Refer to <code className="bg-gray-800 px-1 py-0.5 rounded text-brand-400">.env.example</code> for all available options.
          </p>
          <div className="space-y-3">
            {['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY', 'COHERE_API_KEY'].map((key) => (
              <div key={key} className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
                <code className="text-sm text-gray-300">{key}</code>
                <span className="text-xs text-gray-600">Set in .env</span>
              </div>
            ))}
          </div>
        </div>
        <div className="card space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">Backend</h2>
          <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
            <span className="text-sm text-gray-300">API Base URL</span>
            <code className="text-xs text-brand-400">http://localhost:8000</code>
          </div>
          <div className="flex items-center justify-between p-3 bg-gray-800 rounded-lg">
            <span className="text-sm text-gray-300">API Docs</span>
            <a href="/docs" target="_blank" className="text-xs text-brand-500 hover:text-brand-600">/docs ↗</a>
          </div>
        </div>
      </div>
    </div>
  )
}
