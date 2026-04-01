import client from './client'
import type { AttackTemplate, AttackTemplateCreate, StrategyOptions } from '../types/attack'

export interface AttackFilters {
  level?: number
  attack_type?: string
  domain?: string
  category?: string
  sort_by?: string
  sort_dir?: string
}

export const attacksApi = {
  list: (filters: AttackFilters = {}): Promise<AttackTemplate[]> =>
    client.get('/attacks/', { params: filters }).then((r) => r.data),

  create: (body: AttackTemplateCreate): Promise<AttackTemplate> =>
    client.post('/attacks/', body).then((r) => r.data),

  get: (id: number): Promise<AttackTemplate> =>
    client.get(`/attacks/${id}`).then((r) => r.data),

  mutate: (id: number, strategy = 'random'): Promise<AttackTemplate> =>
    client.post(`/attacks/${id}/mutate`, null, { params: { strategy } }).then((r) => r.data),

  seedStatic: (): Promise<{ message: string }> =>
    client.post('/attacks/seed-static').then((r) => r.data),

  delete: (id: number): Promise<void> =>
    client.delete(`/attacks/${id}`).then((r) => r.data),

  strategyOptions: (): Promise<StrategyOptions> =>
    client.get('/attacks/strategy-options').then((r) => r.data),

  strategyPlan: (body: {
    goal: string
    method: string
    target_vulnerability: string
    domain: string
    steps: string[]
  }): Promise<{ generated_payload: string; estimated_level: number; steps: string[] }> =>
    client.post('/attacks/strategy-plan', body).then((r) => r.data),
}
