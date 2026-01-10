import { Command } from 'commander';
import { AuditLogger } from '../../audit/logger.js';

export const logsCommand = new Command('logs')
  .description('View audit log entries')
  .option('-n, --limit <count>', 'Number of entries to show', '20')
  .option('--tail', 'Follow log in real-time')
  .option('--since <duration>', 'Show entries since duration (e.g., 1h, 30m, 7d)')
  .option('--server <name>', 'Filter by server name')
  .option('--risk <level>', 'Filter by risk level (safe, read, write, destructive, dangerous)')
  .option('--export <format>', 'Export format (json, csv, cef)')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const logger = new AuditLogger();

      // Parse since duration
      let since: Date | undefined;
      if (options.since) {
        since = parseDuration(options.since);
      }

      // Export mode
      if (options.export) {
        const entries = await logger.query({
          since,
          server: options.server,
          riskLevel: options.risk,
          limit: parseInt(options.limit, 10),
        });

        const output = await logger.export(entries, options.export);
        console.log(output);
        return;
      }

      // Tail mode
      if (options.tail) {
        console.log('Following audit log (Ctrl+C to stop)...\n');

        await logger.tail((entry) => {
          printEntry(entry, options.json);
        });

        return;
      }

      // Normal query
      const entries = await logger.query({
        since,
        server: options.server,
        riskLevel: options.risk,
        limit: parseInt(options.limit, 10),
      });

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
    }
  });

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

interface AuditEntry {
  id: string;
  timestamp: Date;
  server?: string;
  tool: string;
  args?: Record<string, unknown>;
  riskLevel: string;
  decision: string;
  duration?: number;
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
