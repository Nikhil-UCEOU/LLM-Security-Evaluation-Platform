import client from './client'

export interface BenchmarkRunRequest {
  dataset: string
  provider: string
  model: string
  system_prompt: string
  max_attacks?: number
  categories?: string[]
}

export interface BenchmarkResult {
  run_id: string
  dataset: string
  provider: string
  model: string
  total_tests: number
  successful_attacks: number
  success_rate: number
  leakage_score: number
  drift_index: number
  risk_level: string
  by_category: Record<string, number>
  by_severity: Record<string, number>
  by_strategy: Record<string, number>
  duration_ms: number
  timestamp: string
}

export interface DatasetInfo {
  name: string
  label: string
  files: number
  total_attacks: number
  categories: string[]
  severities: Record<string, number>
  description?: string
  version?: string
}

export const benchmarkApi = {
  run: (body: BenchmarkRunRequest): Promise<BenchmarkResult> =>
    client.post('/benchmark/run', body).then(r => r.data),

  results: (limit = 20): Promise<BenchmarkResult[]> =>
    client.get('/benchmark/results', { params: { limit } }).then(r => r.data),

  getResult: (runId: string): Promise<BenchmarkResult & { attack_results: any[] }> =>
    client.get(`/benchmark/result/${runId}`).then(r => r.data),

  compare: (runIds: string[]): Promise<{ comparisons: BenchmarkResult[] }> =>
    client.get('/benchmark/compare', { params: { run_ids: runIds.join(',') } }).then(r => r.data),

  datasets: (): Promise<DatasetInfo[]> =>
    client.get('/benchmark/datasets').then(r => r.data),

  seeds: (body: { categories?: string[]; target_n?: number; force_refresh?: boolean }) =>
    client.post('/benchmark/seeds', body).then(r => r.data),

  kb: (limit = 20) =>
    client.get('/benchmark/kb', { params: { limit } }).then(r => r.data),
}
