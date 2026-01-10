import Database from 'better-sqlite3';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import type { Session, SessionAudit, SessionQuery, SessionStats } from './types.js';

/**
 * Persistent SQLite storage for sessions with audit trail support.
 * Implements O-H11 (persistent storage) and O-H12 (audit trail).
 */
export class SessionStore {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const actualPath = dbPath || this.getDefaultPath();
    const dir = path.dirname(actualPath);

    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(actualPath);
    this.initialize();
  }

  private getDefaultPath(): string {
    return path.join(os.homedir(), '.overwatch', 'sessions.db');
  }

  private initialize(): void {
    // Create sessions table with audit trail columns
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        pattern TEXT NOT NULL,
        server TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        -- Audit trail fields (O-H12)
        approver TEXT,
        tool_name TEXT,
        tool_args TEXT,
        risk_level TEXT,
        reason TEXT,
        source TEXT,
        use_count INTEGER DEFAULT 0,
        last_used_at INTEGER,
        -- Revocation fields
        revoked_at INTEGER,
        revoked_by TEXT,
        revoke_reason TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_sessions_server ON sessions(server);
      CREATE INDEX IF NOT EXISTS idx_sessions_scope ON sessions(scope);
      CREATE INDEX IF NOT EXISTS idx_sessions_approver ON sessions(approver);
      CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
    `);

    // Migrate existing tables if needed (add missing columns)
    this.migrateSchema();
  }

  private migrateSchema(): void {
    // Get existing columns
    const tableInfo = this.db.prepare("PRAGMA table_info(sessions)").all() as { name: string }[];
    const existingColumns = new Set(tableInfo.map(col => col.name));

    // Add missing audit columns
    const newColumns = [
      { name: 'approver', type: 'TEXT' },
      { name: 'tool_name', type: 'TEXT' },
      { name: 'tool_args', type: 'TEXT' },
      { name: 'risk_level', type: 'TEXT' },
      { name: 'reason', type: 'TEXT' },
      { name: 'source', type: 'TEXT' },
      { name: 'use_count', type: 'INTEGER DEFAULT 0' },
      { name: 'last_used_at', type: 'INTEGER' },
      { name: 'revoked_at', type: 'INTEGER' },
      { name: 'revoked_by', type: 'TEXT' },
      { name: 'revoke_reason', type: 'TEXT' },
    ];

    for (const col of newColumns) {
      if (!existingColumns.has(col.name)) {
        this.db.exec(`ALTER TABLE sessions ADD COLUMN ${col.name} ${col.type}`);
      }
    }
  }

  save(session: Session): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO sessions (
        id, scope, pattern, server, created_at, expires_at,
        approver, tool_name, tool_args, risk_level, reason, source,
        use_count, last_used_at, revoked_at, revoked_by, revoke_reason
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const audit = session.audit;
    const revocation = audit?.revocation;

    stmt.run(
      session.id,
      session.scope,
      session.pattern,
      session.server || null,
      session.createdAt.getTime(),
      session.expiresAt.getTime(),
      audit?.approver || null,
      audit?.toolName || null,
      audit?.toolArgs || null,
      audit?.riskLevel || null,
      audit?.reason || null,
      audit?.source || null,
      audit?.useCount || 0,
      audit?.lastUsedAt?.getTime() || null,
      revocation?.revokedAt.getTime() || null,
      revocation?.revokedBy || null,
      revocation?.reason || null
    );
  }

  get(id: string): Session | null {
    const stmt = this.db.prepare('SELECT * FROM sessions WHERE id = ?');
    const row = stmt.get(id) as SessionRow | undefined;

    if (!row) return null;

    return this.rowToSession(row);
  }

  /**
   * List sessions with optional filtering.
   */
  list(query?: SessionQuery): Session[] {
    let sql = 'SELECT * FROM sessions WHERE 1=1';
    const params: unknown[] = [];

    if (query?.activeOnly !== false) {
      sql += ' AND expires_at > ? AND revoked_at IS NULL';
      params.push(Date.now());
    }

    if (query?.server) {
      sql += ' AND (server = ? OR server IS NULL)';
      params.push(query.server);
    }

    if (query?.pattern) {
      sql += ' AND pattern = ?';
      params.push(query.pattern);
    }

    if (query?.scope) {
      sql += ' AND scope = ?';
      params.push(query.scope);
    }

    sql += ' ORDER BY created_at DESC';

    if (query?.limit) {
      sql += ' LIMIT ?';
      params.push(query.limit);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as SessionRow[];

    return rows.map(row => this.rowToSession(row));
  }

  /**
   * Find matching session for a tool call.
   */
  findMatch(tool: string, server?: string): Session | null {
    const now = Date.now();

    // Get all active, non-revoked sessions
    const stmt = this.db.prepare(`
      SELECT * FROM sessions
      WHERE expires_at > ? AND revoked_at IS NULL
      ORDER BY created_at DESC
    `);
    const rows = stmt.all(now) as SessionRow[];

    for (const row of rows) {
      const session = this.rowToSession(row);

      // Check server match
      if (session.server && session.server !== server) {
        continue;
      }

      // Check pattern match
      switch (session.scope) {
        case 'exact':
          if (session.pattern === tool) {
            return session;
          }
          break;

        case 'tool':
          if (this.matchPattern(session.pattern, tool)) {
            return session;
          }
          break;

        case 'server':
          if (!session.server || session.server === server) {
            return session;
          }
          break;
      }
    }

    return null;
  }

  /**
   * Record session usage (O-H12).
   */
  recordUsage(id: string): void {
    const stmt = this.db.prepare(`
      UPDATE sessions
      SET use_count = use_count + 1, last_used_at = ?
      WHERE id = ?
    `);
    stmt.run(Date.now(), id);
  }

  /**
   * Revoke a session with audit trail (O-H13).
   */
  revoke(id: string, revokedBy: string, reason?: string): boolean {
    const stmt = this.db.prepare(`
      UPDATE sessions
      SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
      WHERE id = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(Date.now(), revokedBy, reason || null, id);
    return result.changes > 0;
  }

  /**
   * Revoke sessions matching criteria (O-H13).
   */
  revokeByPattern(pattern: string, revokedBy: string, reason?: string): number {
    const stmt = this.db.prepare(`
      UPDATE sessions
      SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
      WHERE pattern = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(Date.now(), revokedBy, reason || null, pattern);
    return result.changes;
  }

  /**
   * Revoke all sessions for a server (O-H13).
   */
  revokeByServer(server: string, revokedBy: string, reason?: string): number {
    const stmt = this.db.prepare(`
      UPDATE sessions
      SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
      WHERE server = ? AND revoked_at IS NULL
    `);
    const result = stmt.run(Date.now(), revokedBy, reason || null, server);
    return result.changes;
  }

  /**
   * Delete a session permanently.
   */
  delete(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Delete all sessions.
   */
  deleteAll(): number {
    const stmt = this.db.prepare('DELETE FROM sessions');
    const result = stmt.run();
    return result.changes;
  }

  /**
   * Prune expired sessions.
   */
  prune(): number {
    const stmt = this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
    const result = stmt.run(Date.now());
    return result.changes;
  }

  /**
   * Get session statistics.
   */
  getStats(): SessionStats {
    const now = Date.now();

    // Total counts
    const countStmt = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN expires_at > ? AND revoked_at IS NULL THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END) as expired,
        SUM(CASE WHEN revoked_at IS NOT NULL THEN 1 ELSE 0 END) as revoked,
        SUM(use_count) as total_approvals
      FROM sessions
    `);
    const counts = countStmt.get(now, now) as {
      total: number;
      active: number;
      expired: number;
      revoked: number;
      total_approvals: number;
    };

    // By scope
    const scopeStmt = this.db.prepare(`
      SELECT scope, COUNT(*) as count
      FROM sessions
      WHERE expires_at > ? AND revoked_at IS NULL
      GROUP BY scope
    `);
    const scopeRows = scopeStmt.all(now) as { scope: string; count: number }[];
    const byScope: Record<string, number> = {};
    for (const row of scopeRows) {
      byScope[row.scope] = row.count;
    }

    // By server
    const serverStmt = this.db.prepare(`
      SELECT server, COUNT(*) as count
      FROM sessions
      WHERE expires_at > ? AND revoked_at IS NULL AND server IS NOT NULL
      GROUP BY server
    `);
    const serverRows = serverStmt.all(now) as { server: string; count: number }[];
    const byServer: Record<string, number> = {};
    for (const row of serverRows) {
      byServer[row.server] = row.count;
    }

    return {
      totalSessions: counts.total,
      activeSessions: counts.active,
      expiredSessions: counts.expired,
      revokedSessions: counts.revoked,
      byScope,
      byServer,
      totalApprovals: counts.total_approvals || 0,
    };
  }

  findByPattern(pattern: string, server?: string): Session[] {
    let stmt;
    let rows: SessionRow[];

    if (server) {
      stmt = this.db.prepare(`
        SELECT * FROM sessions
        WHERE pattern = ? AND (server = ? OR server IS NULL)
        AND expires_at > ? AND revoked_at IS NULL
      `);
      rows = stmt.all(pattern, server, Date.now()) as SessionRow[];
    } else {
      stmt = this.db.prepare(`
        SELECT * FROM sessions
        WHERE pattern = ? AND expires_at > ? AND revoked_at IS NULL
      `);
      rows = stmt.all(pattern, Date.now()) as SessionRow[];
    }

    return rows.map(row => this.rowToSession(row));
  }

  close(): void {
    this.db.close();
  }

  private matchPattern(pattern: string, tool: string): boolean {
    if (pattern === '*') {
      return true;
    }

    if (pattern.endsWith('*')) {
      const prefix = pattern.slice(0, -1);
      return tool.startsWith(prefix);
    }

    if (pattern.startsWith('*')) {
      const suffix = pattern.slice(1);
      return tool.endsWith(suffix);
    }

    return pattern === tool;
  }

  private rowToSession(row: SessionRow): Session {
    const session: Session = {
      id: row.id,
      scope: row.scope as Session['scope'],
      pattern: row.pattern,
      server: row.server || undefined,
      createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at),
    };

    // Add audit info if present
    if (row.approver || row.tool_name) {
      const audit: SessionAudit = {
        approver: row.approver || 'unknown',
        toolName: row.tool_name || 'unknown',
        toolArgs: row.tool_args || undefined,
        riskLevel: row.risk_level || undefined,
        reason: row.reason || undefined,
        source: row.source || undefined,
        useCount: row.use_count || 0,
        lastUsedAt: row.last_used_at ? new Date(row.last_used_at) : undefined,
      };

      // Add revocation info if present
      if (row.revoked_at) {
        audit.revocation = {
          revokedAt: new Date(row.revoked_at),
          revokedBy: row.revoked_by || 'unknown',
          reason: row.revoke_reason || undefined,
        };
      }

      session.audit = audit;
    }

    return session;
  }
}

interface SessionRow {
  id: string;
  scope: string;
  pattern: string;
  server: string | null;
  created_at: number;
  expires_at: number;
  // Audit fields
  approver: string | null;
  tool_name: string | null;
  tool_args: string | null;
  risk_level: string | null;
  reason: string | null;
  source: string | null;
  use_count: number | null;
  last_used_at: number | null;
  // Revocation fields
  revoked_at: number | null;
  revoked_by: string | null;
  revoke_reason: string | null;
}
