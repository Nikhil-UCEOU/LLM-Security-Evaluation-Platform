import client from './client'
import type { EvaluationRunRequest, EvaluationSummary, EvaluationRun, PipelineReport } from '../types/evaluation'

export const evaluationsApi = {
  run: (request: EvaluationRunRequest): Promise<PipelineReport> =>
    client.post('/evaluations/run', request).then((r) => r.data),

  list: (limit = 20): Promise<EvaluationSummary[]> =>
    client.get('/evaluations/', { params: { limit } }).then((r) => r.data),

  get: (runId: number): Promise<EvaluationRun> =>
    client.get(`/evaluations/${runId}`).then((r) => r.data),

  getReport: (runId: number): Promise<object> =>
    client.get(`/evaluations/${runId}/report`).then((r) => r.data),
}
