export interface Session {
  id: string;
  scope: 'exact' | 'tool' | 'server';
  pattern: string;
  server?: string;
  createdAt: Date;
  expiresAt: Date;
  // Audit trail fields (O-H12)
  audit?: SessionAudit;
}

/**
 * Audit trail information for session creation.
 * Tracks who approved what, when, and why.
 */
export interface SessionAudit {
  /** Who approved/created this session */
  approver: string;
  /** The tool that was approved */
  toolName: string;
  /** Arguments to the tool (serialized) */
  toolArgs?: string;
  /** Risk level that was assessed */
  riskLevel?: string;
  /** Reason for approval (user-provided or auto) */
  reason?: string;
  /** IP address or identifier of approver */
  source?: string;
  /** Number of times this session was used */
  useCount: number;
  /** Last time this session was used */
  lastUsedAt?: Date;
  /** Revocation info if session was revoked */
  revocation?: SessionRevocation;
}

/**
 * Information about session revocation.
 */
export interface SessionRevocation {
  revokedAt: Date;
  revokedBy: string;
  reason?: string;
}

export interface SessionGrant {
  sessionId: string;
  tool: string;
  server?: string;
  duration: number;
}

export type SessionDuration = 'once' | '5min' | '15min' | 'session' | number;

/**
 * Options for session creation with audit context.
 */
export interface SessionCreateOptions {
  scope: 'exact' | 'tool' | 'server';
  pattern: string;
  duration: SessionDuration;
  server?: string;
  // Audit context
  approver?: string;
  toolName?: string;
  toolArgs?: Record<string, unknown>;
  riskLevel?: string;
  reason?: string;
  source?: string;
}

/**
 * Query options for finding sessions.
 */
export interface SessionQuery {
  server?: string;
  pattern?: string;
  scope?: 'exact' | 'tool' | 'server';
  activeOnly?: boolean;
  limit?: number;
}

/**
 * Session manager configuration.
 */
export interface SessionManagerConfig {
  /** Path to SQLite database (null for in-memory) */
  dbPath?: string | null;
  /** Interval for background cleanup in milliseconds (default: 60000) */
  cleanupIntervalMs?: number;
  /** Whether to enable background cleanup (default: true) */
  enableBackgroundCleanup?: boolean;
}

/**
 * Session statistics.
 */
export interface SessionStats {
  totalSessions: number;
  activeSessions: number;
  expiredSessions: number;
  revokedSessions: number;
  byScope: Record<string, number>;
  byServer: Record<string, number>;
  totalApprovals: number;
  lastCleanup?: Date;
}
