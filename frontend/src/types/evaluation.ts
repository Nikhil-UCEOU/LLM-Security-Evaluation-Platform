export type RunStatus = 'pending' | 'running' | 'completed' | 'failed'
export type Classification = 'safe' | 'unsafe' | 'partial' | 'unknown'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface EvaluationRunRequest {
  provider: string
  model: string
  system_prompt: string
  attack_categories: string[]
  include_adaptive: boolean
  max_attacks: number
}

export interface EvaluationResult {
  id: number
  run_id: number
  attack_name: string
  attack_payload: string
  response_text: string
  classification: Classification
  severity: Severity
  latency_ms: number
  tokens_used: number
  isr_contribution: number
  created_at: string
}

export interface EvaluationRun {
  id: number
  provider: string
  model: string
  system_prompt: string
  status: RunStatus
  global_isr: number | null
  started_at: string
  completed_at: string | null
  results: EvaluationResult[]
}

export interface EvaluationSummary {
  run_id: number
  provider: string
  model: string
  status: RunStatus
  global_isr: number | null
  total_attacks: number
  unsafe_count: number
  critical_count: number
  started_at: string
  completed_at: string | null
}

export interface PipelineReport {
  run_id: number
  status: string
  provider: string
  model: string
  global_isr: number
  isr_by_category: Record<string, number>
  total_attacks: number
  successful_attacks: number
  severity_distribution: Record<string, number>
  rca_summary: {
    root_causes: number
    patterns: number
    behavioral_analysis: string
  }
  mitigation: {
    strategy: string
    original_isr: number
    hardened_isr: number
    improvement_pct: number
  }
}
