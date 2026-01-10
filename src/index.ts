// Overwatch - Runtime security for AI-augmented development
// Main library exports

export { loadConfig, validateConfig } from './config/loader.js';
export type { OverwatchConfig, ServerConfig, PolicyConfig, RiskLevel } from './config/types.js';

export { TollgateBridge } from './proxy/bridge.js';
export { Orchestrator } from './proxy/orchestrator.js';
export {
  ToolShadowingDetector,
  toolShadowingDetector,
} from './proxy/tool-shadowing.js';
export type {
  Tool,
  ToolSchemaHash,
  ShadowingCheckResult,
  ShadowingDetails,
  ServerShadowingReport,
} from './proxy/tool-shadowing.js';


export { SessionManager } from './session/manager.js';
export type { Session, SessionDuration } from './session/types.js';

export { AuditLogger } from './audit/logger.js';
export type { AuditEntry, AuditQuery, AuditStats } from './audit/logger.js';

// Approval handlers
export {
  TerminalApprovalHandler,
  createTerminalApprovalHandler,
  WebhookApprovalHandler,
  createWebhookApprovalHandler,
  verifyWebhookSignature,
  verifyWebhookSignatureDetailed,
} from './approval/index.js';
export type {
  ApprovalHandler,
  ApprovalRequest,
  ApprovalResponse,
  ApprovalCallback,
  WebhookApprovalConfig,
  WebhookPayload,
  WebhookVerificationResult,
} from './approval/index.js';
