export type AttackCategory =
  | 'prompt_injection' | 'jailbreak' | 'role_play'
  | 'indirect_injection' | 'context_manipulation' | 'multi_turn'
  | 'payload_encoding' | 'rag_poisoning' | 'api_abuse'
  | 'cognitive' | 'strategy_based'

export type AttackType = 'prompt' | 'rag' | 'api' | 'strategy' | 'document'
export type AttackDomain = 'general' | 'finance' | 'healthcare' | 'legal' | 'hr' | 'security'
export type AttackSource = 'static' | 'adaptive' | 'manual' | 'strategy'

export interface AttackTemplate {
  id: number
  name: string
  category: AttackCategory
  attack_type: AttackType
  level: number
  domain: AttackDomain
  description: string
  payload_template: string
  source: AttackSource
  is_active: boolean
  strategy_goal: string
  strategy_method: string
  strategy_vulnerability: string
  strategy_steps: string[]
  success_rate: number
  risk_score: number
  mutation_count: number
  parent_id: number | null
  created_at: string
}

export interface AttackTemplateCreate {
  name: string
  category: AttackCategory
  attack_type: AttackType
  level: number
  domain: AttackDomain
  description: string
  payload_template: string
  source: AttackSource
  strategy_goal: string
  strategy_method: string
  strategy_vulnerability: string
  strategy_steps: string[]
  risk_score: number
}

export interface StrategyOption {
  value: string
  label: string
}

export interface StrategyOptions {
  methods: StrategyOption[]
  vulnerabilities: StrategyOption[]
  domains: StrategyOption[]
  goals: StrategyOption[]
}
