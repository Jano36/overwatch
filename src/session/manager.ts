import * as crypto from 'crypto';
import { SessionStore } from './store.js';
import type {
  Session,
  SessionDuration,
  SessionCreateOptions,
  SessionQuery,
  SessionStats,
  SessionManagerConfig,
} from './types.js';

/**
 * Session manager with persistent SQLite storage and background cleanup.
 * Implements O-H11 (persistent storage), O-H12 (audit trail),
 * O-H13 (revocation), and O-H14 (background cleanup).
 */
export class SessionManager {
  private store: SessionStore;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;
  private lastCleanup: Date | null = null;
  private config: Required<SessionManagerConfig>;

  constructor(config?: SessionManagerConfig) {
    this.config = {
      dbPath: config?.dbPath ?? null,
      cleanupIntervalMs: config?.cleanupIntervalMs ?? 60000, // Default: 1 minute
      enableBackgroundCleanup: config?.enableBackgroundCleanup ?? true,
    };

    // Initialize persistent store (null means in-memory)
    this.store = new SessionStore(this.config.dbPath ?? undefined);

    // Start background cleanup if enabled (O-H14)
    if (this.config.enableBackgroundCleanup) {
      this.startBackgroundCleanup();
    }
  }

  /**
   * Start background cleanup timer (O-H14).
   */
  private startBackgroundCleanup(): void {
    if (this.cleanupTimer) {
      return;
    }

    this.cleanupTimer = setInterval(() => {
      this.runCleanup();
    }, this.config.cleanupIntervalMs);

    // Ensure timer doesn't prevent process exit
    this.cleanupTimer.unref?.();
  }

  /**
   * Run cleanup of expired sessions.
   */
  private runCleanup(): void {
    try {
      const pruned = this.store.prune();
      this.lastCleanup = new Date();
      if (pruned > 0) {
        // Could add logging here
      }
    } catch {
      // Silently handle cleanup errors to avoid crashing background timer
    }
  }

  /**
   * Stop background cleanup timer.
   */
  stopBackgroundCleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  /**
   * List active sessions.
   */
  async list(query?: SessionQuery): Promise<Session[]> {
    return this.store.list(query);
  }

  /**
   * Create a new session with optional audit context.
   */
  async create(options: SessionCreateOptions): Promise<Session>;
  async create(
    scope: 'exact' | 'tool' | 'server',
    pattern: string,
    duration: SessionDuration,
    server?: string
  ): Promise<Session>;
  async create(
    scopeOrOptions: 'exact' | 'tool' | 'server' | SessionCreateOptions,
    pattern?: string,
    duration?: SessionDuration,
    server?: string
  ): Promise<Session> {
    // Handle overload
    const options: SessionCreateOptions =
      typeof scopeOrOptions === 'string'
        ? {
            scope: scopeOrOptions,
            pattern: pattern!,
            duration: duration!,
            server,
          }
        : scopeOrOptions;

    const id = crypto.randomBytes(16).toString('hex');
    const now = new Date();

    let expiresAt: Date;
    switch (options.duration) {
      case 'once':
        expiresAt = new Date(now.getTime() + 1000); // 1 second
        break;
      case '5min':
        expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
        break;
      case '15min':
        expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
        break;
      case 'session':
        expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
        break;
      default:
        expiresAt = new Date(now.getTime() + options.duration);
    }

    const session: Session = {
      id,
      scope: options.scope,
      pattern: options.pattern,
      server: options.server,
      createdAt: now,
      expiresAt,
    };

    // Add audit trail if context provided (O-H12)
    if (options.approver || options.toolName) {
      session.audit = {
        approver: options.approver || 'system',
        toolName: options.toolName || options.pattern,
        toolArgs: options.toolArgs ? JSON.stringify(options.toolArgs) : undefined,
        riskLevel: options.riskLevel,
        reason: options.reason,
        source: options.source,
        useCount: 0,
      };
    }

    // Persist to SQLite (O-H11)
    this.store.save(session);

    return session;
  }

  /**
   * Check if a tool call is covered by an active session.
   * Records usage for audit trail.
   */
  async check(tool: string, server?: string): Promise<Session | null> {
    const session = this.store.findMatch(tool, server);

    if (session) {
      // Record usage for audit trail (O-H12)
      this.store.recordUsage(session.id);
    }

    return session;
  }

  /**
   * Revoke a session by ID (O-H13).
   */
  async revoke(id: string, revokedBy?: string, reason?: string): Promise<boolean> {
    return this.store.revoke(id, revokedBy || 'user', reason);
  }

  /**
   * Revoke all sessions matching a pattern (O-H13).
   */
  async revokeByPattern(pattern: string, revokedBy?: string, reason?: string): Promise<number> {
    return this.store.revokeByPattern(pattern, revokedBy || 'user', reason);
  }

  /**
   * Revoke all sessions for a server (O-H13).
   */
  async revokeByServer(server: string, revokedBy?: string, reason?: string): Promise<number> {
    return this.store.revokeByServer(server, revokedBy || 'user', reason);
  }

  /**
   * Revoke all active sessions.
   */
  async revokeAll(revokedBy?: string, reason?: string): Promise<number> {
    const sessions = await this.list({ activeOnly: true });
    let count = 0;
    for (const session of sessions) {
      if (await this.revoke(session.id, revokedBy, reason)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get session by ID.
   */
  async get(id: string): Promise<Session | null> {
    return this.store.get(id);
  }

  /**
   * Get session statistics.
   */
  async getStats(): Promise<SessionStats> {
    const stats = this.store.getStats();
    return {
      ...stats,
      lastCleanup: this.lastCleanup || undefined,
    };
  }

  /**
   * Manually trigger cleanup of expired sessions.
   */
  async cleanup(): Promise<number> {
    const pruned = this.store.prune();
    this.lastCleanup = new Date();
    return pruned;
  }

  /**
   * Close the session manager and release resources.
   */
  async close(): Promise<void> {
    this.stopBackgroundCleanup();
    this.store.close();
  }

  /**
   * Get sessions by pattern.
   */
  async findByPattern(pattern: string, server?: string): Promise<Session[]> {
    return this.store.findByPattern(pattern, server);
  }
}
