export type {
  OverwatchConfig,
  DefaultsConfig,
  ServerConfig,
  PolicyConfig,
  AuditConfig,
  RiskLevel,
  ToolShadowingConfig,
} from './types.js';

export { loadConfig, validateConfig } from './loader.js';
export type { ValidationResult } from './loader.js';

export {
  templates,
  getTemplate,
  listTemplates,
  applyTemplate,
  generateConfig,
  commonDenyPatterns,
  guardrailPatterns,
  filesystemTemplate,
  databaseTemplate,
  httpTemplate,
  shellTemplate,
  codingAssistantTemplate,
  strictTemplate,
  auditOnlyTemplate,
} from './templates.js';
export type { PolicyTemplate } from './templates.js';
