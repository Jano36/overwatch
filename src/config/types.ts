export interface OverwatchConfig {
  version: number;
  defaults?: DefaultsConfig;
  servers?: Record<string, ServerConfig>;
  audit?: AuditConfig;
  toolShadowing?: ToolShadowingConfig;
}

export interface ToolShadowingConfig {
  enabled?: boolean;
  checkDescriptions?: boolean;
  detectMutations?: boolean;
}

export interface DefaultsConfig {
  action?: 'prompt' | 'allow' | 'deny';
  timeout?: number;
  sessionDuration?: number;
}

export interface ServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  policies?: PolicyConfig[];
}

export interface PolicyConfig {
  tools?: string | string[];
  /** @deprecated Analyzer field is no longer used - analyzers were removed in Phase 1 */
  analyzer?: string;
  action?: 'allow' | 'prompt' | 'deny' | 'smart';
  paths?: {
    allow?: string[];
    deny?: string[];
  };
}

export interface AuditConfig {
  enabled?: boolean;
  path?: string;
  redactPII?: boolean;
  retention?: string;
}

export type RiskLevel = 'safe' | 'read' | 'write' | 'destructive' | 'dangerous';
