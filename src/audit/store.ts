import Database from 'better-sqlite3';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import type { AuditEntry, AuditQuery, AuditStats } from './logger.js';
import type { RiskLevel } from '../config/types.js';

export class AuditStore {
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
    return path.join(os.homedir(), '.overwatch', 'audit.db');
  }

  private initialize(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_entries (
        id TEXT PRIMARY KEY,
        timestamp INTEGER NOT NULL,
        server TEXT,
        tool TEXT NOT NULL,
        args TEXT,
        risk_level TEXT NOT NULL,
        decision TEXT NOT NULL,
        session_id TEXT,
        duration INTEGER,
        error TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
      CREATE INDEX IF NOT EXISTS idx_audit_server ON audit_entries(server);
      CREATE INDEX IF NOT EXISTS idx_audit_risk_level ON audit_entries(risk_level);
      CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_entries(decision);
    `);
  }

  save(entry: AuditEntry): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_entries
      (id, timestamp, server, tool, args, risk_level, decision, session_id, duration, error)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      entry.id,
      entry.timestamp.getTime(),
      entry.server || null,
      entry.tool,
      entry.args ? JSON.stringify(entry.args) : null,
      entry.riskLevel,
      entry.decision,
      entry.sessionId || null,
      entry.duration || null,
      entry.error || null
    );
  }

  query(options: AuditQuery): AuditEntry[] {
    let sql = 'SELECT * FROM audit_entries WHERE 1=1';
    const params: unknown[] = [];

    if (options.since) {
      sql += ' AND timestamp >= ?';
      params.push(options.since.getTime());
    }

    if (options.until) {
      sql += ' AND timestamp <= ?';
      params.push(options.until.getTime());
    }

    if (options.server) {
      sql += ' AND server = ?';
      params.push(options.server);
    }

    if (options.tool) {
      sql += ' AND tool = ?';
      params.push(options.tool);
    }

    if (options.riskLevel) {
      sql += ' AND risk_level = ?';
      params.push(options.riskLevel);
    }

    if (options.decision) {
      sql += ' AND decision = ?';
      params.push(options.decision);
    }

    sql += ' ORDER BY timestamp DESC';

    if (options.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as AuditRow[];

    return rows.map(row => this.rowToEntry(row));
  }

  getStats(since?: Date): AuditStats {
    let whereClause = '';
    const params: unknown[] = [];

    if (since) {
      whereClause = 'WHERE timestamp >= ?';
      params.push(since.getTime());
    }

    // Total and decision counts
    const countStmt = this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN decision = 'allowed' THEN 1 ELSE 0 END) as allowed,
        SUM(CASE WHEN decision = 'denied' THEN 1 ELSE 0 END) as denied
      FROM audit_entries
      ${whereClause}
    `);
    const counts = countStmt.get(...params) as { total: number; allowed: number; denied: number };

    // By risk level
    const riskStmt = this.db.prepare(`
      SELECT risk_level, COUNT(*) as count
      FROM audit_entries
      ${whereClause}
      GROUP BY risk_level
    `);
    const riskRows = riskStmt.all(...params) as { risk_level: string; count: number }[];
    const byRiskLevel = {} as Record<RiskLevel, number>;
    for (const row of riskRows) {
      byRiskLevel[row.risk_level as RiskLevel] = row.count;
    }

    // By server
    const serverStmt = this.db.prepare(`
      SELECT server, COUNT(*) as count
      FROM audit_entries
      ${whereClause}
      ${whereClause ? 'AND' : 'WHERE'} server IS NOT NULL
      GROUP BY server
    `);
    const serverParams = since ? [...params] : params;
    const serverRows = serverStmt.all(...serverParams) as { server: string; count: number }[];
    const byServer: Record<string, number> = {};
    for (const row of serverRows) {
      byServer[row.server] = row.count;
    }

    // Top tools
    const toolStmt = this.db.prepare(`
      SELECT tool, COUNT(*) as count
      FROM audit_entries
      ${whereClause}
      GROUP BY tool
      ORDER BY count DESC
      LIMIT 10
    `);
    const toolRows = toolStmt.all(...params) as { tool: string; count: number }[];
    const topTools = toolRows.map(row => ({ name: row.tool, count: row.count }));

    return {
      total: counts.total,
      allowed: counts.allowed,
      denied: counts.denied,
      byRiskLevel,
      byServer,
      topTools,
    };
  }

  delete(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM audit_entries WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  prune(before: Date): number {
    const stmt = this.db.prepare('DELETE FROM audit_entries WHERE timestamp < ?');
    const result = stmt.run(before.getTime());
    return result.changes;
  }

  close(): void {
    this.db.close();
  }

  private rowToEntry(row: AuditRow): AuditEntry {
    return {
      id: row.id,
      timestamp: new Date(row.timestamp),
      server: row.server || undefined,
      tool: row.tool,
      args: row.args ? JSON.parse(row.args) : undefined,
      riskLevel: row.risk_level as RiskLevel,
      decision: row.decision as 'allowed' | 'denied',
      sessionId: row.session_id || undefined,
      duration: row.duration || undefined,
      error: row.error || undefined,
    };
  }
}

interface AuditRow {
  id: string;
  timestamp: number;
  server: string | null;
  tool: string;
  args: string | null;
  risk_level: string;
  decision: string;
  session_id: string | null;
  duration: number | null;
  error: string | null;
}
