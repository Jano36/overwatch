// Analyzers removed in favor of focusing on core features:
// - Tool Shadowing Detection
// - MCP Proxy with Policy Engine
// - Session Management
//
// SQL, Filesystem, HTTP, and Prompt Injection analyzers were removed
// as they are better handled by dedicated tools (WAFs, SQLi tools, OS controls).

export type { Analyzer, AnalysisResult, AnalysisContext, AnalyzerFactory } from './types.js';

import type { Analyzer } from './types.js';

// No analyzers are currently registered
const analyzers: Record<string, Analyzer> = {};

export function getAnalyzer(name: string): Analyzer | undefined {
  return analyzers[name];
}

export function getAllAnalyzers(): Record<string, Analyzer> {
  return { ...analyzers };
}
