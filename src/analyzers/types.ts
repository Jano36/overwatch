import type { RiskLevel } from '../config/types.js';

export interface AnalysisResult {
  riskLevel: RiskLevel;
  reason?: string;
  details?: Record<string, unknown>;
}

export interface Analyzer {
  name: string;
  analyze(content: string, context?: AnalysisContext): AnalysisResult;
}

export interface AnalysisContext {
  tool?: string;
  server?: string;
  path?: string;
}

export type AnalyzerFactory = () => Analyzer;
