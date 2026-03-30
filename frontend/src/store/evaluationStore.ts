import { create } from 'zustand'
import type { EvaluationSummary, PipelineReport } from '../types/evaluation'
import { evaluationsApi } from '../api/evaluations'

interface EvaluationStore {
  summaries: EvaluationSummary[]
  lastReport: PipelineReport | null
  loading: boolean
  error: string | null
  fetchSummaries: () => Promise<void>
  runEvaluation: (request: object) => Promise<PipelineReport>
}

export const useEvaluationStore = create<EvaluationStore>((set) => ({
  summaries: [],
  lastReport: null,
  loading: false,
  error: null,

  fetchSummaries: async () => {
    set({ loading: true, error: null })
    try {
      const summaries = await evaluationsApi.list()
      set({ summaries, loading: false })
    } catch (e: any) {
      set({ error: e.message, loading: false })
    }
  },

  runEvaluation: async (request) => {
    set({ loading: true, error: null })
    try {
      const report = await evaluationsApi.run(request as any)
      set({ lastReport: report, loading: false })
      return report
    } catch (e: any) {
      set({ error: e.message, loading: false })
      throw e
    }
  },
}))
