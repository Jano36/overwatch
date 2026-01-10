import { Command } from 'commander';
import { AuditStore } from '../../audit/store.js';
import type { AuditEntry } from '../../audit/logger.js';

export const logsCommand = new Command('logs')
  .description('View audit log entries')
  .option('-n, --limit <count>', 'Number of entries to show', '20')
  .option('--tail', 'Follow log in real-time (not supported with persistent storage)')
  .option('--since <duration>', 'Show entries since duration (e.g., 1h, 30m, 7d)')
  .option('--server <name>', 'Filter by server name')
  .option('--risk <level>', 'Filter by risk level (safe, read, write, destructive, dangerous)')
  .option('--export <format>', 'Export format (json, csv, cef)')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    // T3-10: Use AuditStore (SQLite) for persistence instead of in-memory AuditLogger
    let store: AuditStore | undefined;
    try {
      store = new AuditStore();

      // Parse since duration
      let since: Date | undefined;
      if (options.since) {
        since = parseDuration(options.since);
      }

      // Tail mode - not supported with SQLite store (would require polling)
      if (options.tail) {
        console.log('Note: Real-time tailing is not supported with persistent storage.');
        console.log('Showing recent entries instead...\n');
      }

      // Query from persistent store
      const entries = store.query({
        since,
        server: options.server,
        riskLevel: options.risk,
        limit: parseInt(options.limit, 10),
      });

      // Export mode
      if (options.export) {
        const output = exportEntries(entries, options.export);
        console.log(output);
        return;
      }

      if (options.json) {
        console.log(JSON.stringify(entries, null, 2));
        return;
      }

      if (entries.length === 0) {
        console.log('No audit entries found');
        return;
      }

      console.log(`Recent audit entries (${entries.length}):\n`);

      for (const entry of entries) {
        printEntry(entry, false);
      }
    } catch (error) {
      console.error('Failed to query logs:', error);
      process.exit(1);
    } finally {
      store?.close();
    }
  });

/**
 * Export entries to the specified format (T3-10).
 */
function exportEntries(entries: AuditEntry[], format: string): string {
  switch (format.toLowerCase()) {
    case 'json':
      return JSON.stringify(entries, null, 2);

    case 'csv': {
      const headers = ['id', 'timestamp', 'server', 'tool', 'riskLevel', 'decision', 'args'];
      const rows = entries.map(e => [
        e.id,
        e.timestamp.toISOString(),
        e.server || '',
        e.tool,
        e.riskLevel,
        e.decision,
        e.args ? JSON.stringify(e.args) : '',
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
      return [headers.join(','), ...rows].join('\n');
    }

    case 'cef': {
      // Common Event Format for SIEM integration
      return entries.map(e => {
        const severity = e.decision === 'denied' ? 7 : (e.riskLevel === 'dangerous' ? 5 : 3);
        return `CEF:0|Overwatch|MCP|1.0|${e.tool}|Tool Call|${severity}|` +
          `rt=${e.timestamp.getTime()} ` +
          `src=${e.server || 'unknown'} ` +
          `act=${e.decision} ` +
          `cs1=${e.riskLevel} cs1Label=riskLevel`;
      }).join('\n');
    }

    default:
      throw new Error(`Unknown export format: ${format}. Supported: json, csv, cef`);
  }
}

function parseDuration(duration: string): Date {
  const match = duration.match(/^(\d+)([mhd])$/);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Use format like 30m, 1h, 7d`);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  const now = Date.now();
  let ms: number;

  switch (unit) {
    case 'm':
      ms = value * 60 * 1000;
      break;
    case 'h':
      ms = value * 60 * 60 * 1000;
      break;
    case 'd':
      ms = value * 24 * 60 * 60 * 1000;
      break;
    default:
      throw new Error(`Unknown duration unit: ${unit}`);
  }

  return new Date(now - ms);
}

function printEntry(entry: AuditEntry, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(entry));
    return;
  }

  const time = entry.timestamp.toLocaleTimeString();
  const risk = entry.riskLevel.toUpperCase().padEnd(11);
  const decision = entry.decision === 'allowed' ? '✓' : '✗';
  const server = entry.server || 'shell';

  console.log(`  ${time}  ${decision}  ${risk}  ${server}:${entry.tool}`);

  if (entry.args && Object.keys(entry.args).length > 0) {
    const argsStr = JSON.stringify(entry.args);
    const truncated = argsStr.length > 60 ? argsStr.slice(0, 57) + '...' : argsStr;
    console.log(`           ${truncated}`);
  }
}
