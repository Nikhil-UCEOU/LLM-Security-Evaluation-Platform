import client from './client'
import type { AttackTemplate, AttackTemplateCreate } from '../types/attack'

export const attacksApi = {
  list: (): Promise<AttackTemplate[]> =>
    client.get('/attacks/').then((r) => r.data),

  create: (body: AttackTemplateCreate): Promise<AttackTemplate> =>
    client.post('/attacks/', body).then((r) => r.data),

  seedStatic: (): Promise<{ message: string }> =>
    client.post('/attacks/seed-static').then((r) => r.data),

  delete: (id: number): Promise<void> =>
    client.delete(`/attacks/${id}`).then((r) => r.data),
}
