import type { RiskLevel } from '../config/types.js';

export interface AuditEntry {
  id: string;
  timestamp: Date;
  server?: string;
  tool: string;
  args?: Record<string, unknown>;
  riskLevel: RiskLevel;
  decision: 'allowed' | 'denied';
  sessionId?: string;
  duration?: number;
  error?: string;
}

export interface AuditQuery {
  since?: Date;
  until?: Date;
  server?: string;
  tool?: string;
  riskLevel?: RiskLevel;
  decision?: 'allowed' | 'denied';
  limit?: number;
}

export interface AuditStats {
  total: number;
  allowed: number;
  denied: number;
  byRiskLevel: Record<RiskLevel, number>;
  byServer: Record<string, number>;
  topTools: Array<{ name: string; count: number }>;
}

export class AuditLogger {
  private entries: AuditEntry[] = [];
  private tailCallbacks: Array<(entry: AuditEntry) => void> = [];

  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void> {
    const fullEntry: AuditEntry = {
      ...entry,
      id: crypto.randomUUID(),
      timestamp: new Date(),
    };

    this.entries.push(fullEntry);

    // Notify tail listeners
    for (const callback of this.tailCallbacks) {
      callback(fullEntry);
    }
  }

  async query(options: AuditQuery): Promise<AuditEntry[]> {
    let results = [...this.entries];

    // Apply filters
    if (options.since) {
      results = results.filter(e => e.timestamp >= options.since!);
    }

    if (options.until) {
      results = results.filter(e => e.timestamp <= options.until!);
    }

    if (options.server) {
      results = results.filter(e => e.server === options.server);
    }

    if (options.tool) {
      results = results.filter(e => e.tool === options.tool);
    }

    if (options.riskLevel) {
      results = results.filter(e => e.riskLevel === options.riskLevel);
    }

    if (options.decision) {
      results = results.filter(e => e.decision === options.decision);
    }

    // Sort by timestamp descending (most recent first)
    results.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply limit
    if (options.limit && options.limit > 0) {
      results = results.slice(0, options.limit);
    }

    return results;
  }

  async getStats(since?: Date): Promise<AuditStats> {
    let entries = this.entries;

    if (since) {
      entries = entries.filter(e => e.timestamp >= since);
    }

    const stats: AuditStats = {
      total: entries.length,
      allowed: 0,
      denied: 0,
      byRiskLevel: {} as Record<RiskLevel, number>,
      byServer: {},
      topTools: [],
    };

    const toolCounts = new Map<string, number>();

    for (const entry of entries) {
      // Count decisions
      if (entry.decision === 'allowed') {
        stats.allowed++;
      } else {
        stats.denied++;
      }

      // Count by risk level
      stats.byRiskLevel[entry.riskLevel] = (stats.byRiskLevel[entry.riskLevel] || 0) + 1;

      // Count by server
      if (entry.server) {
        stats.byServer[entry.server] = (stats.byServer[entry.server] || 0) + 1;
      }

      // Count tools
      toolCounts.set(entry.tool, (toolCounts.get(entry.tool) || 0) + 1);
    }

    // Get top tools
    stats.topTools = Array.from(toolCounts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return stats;
  }

  async export(entries: AuditEntry[], format: 'json' | 'csv' | 'cef'): Promise<string> {
    switch (format) {
      case 'json':
        return JSON.stringify(entries, null, 2);

      case 'csv':
        return this.exportCSV(entries);

      case 'cef':
        return this.exportCEF(entries);

      default:
        throw new Error(`Unknown export format: ${format}`);
    }
  }

  async tail(callback: (entry: AuditEntry) => void): Promise<void> {
    this.tailCallbacks.push(callback);

    // Keep alive
    await new Promise(() => {});
  }

  private exportCSV(entries: AuditEntry[]): string {
    const headers = ['id', 'timestamp', 'server', 'tool', 'risk_level', 'decision', 'duration'];
    const rows = entries.map(e => [
      e.id,
      e.timestamp.toISOString(),
      e.server || '',
      e.tool,
      e.riskLevel,
      e.decision,
      e.duration?.toString() || '',
    ]);

    return [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');
  }

  private exportCEF(entries: AuditEntry[]): string {
    return entries.map(e => {
      const severity = this.riskToSeverity(e.riskLevel);
      const extension = [
        `rt=${e.timestamp.getTime()}`,
        `cs1=${e.tool}`,
        `cs1Label=Tool`,
        e.server ? `cs2=${e.server}` : '',
        `cs2Label=Server`,
        `outcome=${e.decision}`,
      ].filter(Boolean).join(' ');

      return `CEF:0|DotsetLabs|Overwatch|1.0|${e.riskLevel}|MCP Tool Call|${severity}|${extension}`;
    }).join('\n');
  }

  private riskToSeverity(risk: RiskLevel): number {
    switch (risk) {
      case 'dangerous':
        return 10;
      case 'destructive':
        return 8;
      case 'write':
        return 5;
      case 'read':
        return 3;
      case 'safe':
      default:
        return 1;
    }
  }
}
