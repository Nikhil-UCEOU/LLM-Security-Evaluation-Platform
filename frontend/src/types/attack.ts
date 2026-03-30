export type AttackCategory =
  | 'prompt_injection'
  | 'jailbreak'
  | 'role_play'
  | 'indirect_injection'
  | 'context_manipulation'
  | 'multi_turn'
  | 'payload_encoding'

export type AttackSource = 'static' | 'adaptive' | 'manual'

export interface AttackTemplate {
  id: number
  name: string
  category: AttackCategory
  description: string
  payload_template: string
  source: AttackSource
  is_active: boolean
  created_at: string
}

export interface AttackTemplateCreate {
  name: string
  category: AttackCategory
  description: string
  payload_template: string
  source: AttackSource
}
