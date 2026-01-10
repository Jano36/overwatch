import { Command } from 'commander';
import { AuditStore } from '../../audit/store.js';

export const statsCommand = new Command('stats')
  .description('Show audit statistics')
  .option('--since <duration>', 'Statistics since duration (e.g., 1h, 30m, 7d)')
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

      const stats = store.getStats(since);

      if (options.json) {
        console.log(JSON.stringify(stats, null, 2));
        return;
      }

      console.log('\nOverwatch Audit Statistics');
      console.log('══════════════════════════════════════════\n');

      // Summary
      console.log('Summary');
      console.log('──────────────────────────────────────────');
      console.log(`  Total operations:     ${stats.total}`);
      console.log(`  Allowed:              ${stats.allowed} (${percent(stats.allowed, stats.total)})`);
      console.log(`  Denied:               ${stats.denied} (${percent(stats.denied, stats.total)})`);
      console.log(`  Time period:          ${options.since || 'all time'}`);
      console.log();

      // By risk level
      if (stats.byRiskLevel && Object.keys(stats.byRiskLevel).length > 0) {
        console.log('By Risk Level');
        console.log('──────────────────────────────────────────');
        for (const [level, count] of Object.entries(stats.byRiskLevel)) {
          const bar = '█'.repeat(Math.ceil((count as number / stats.total) * 20));
          console.log(`  ${level.padEnd(12)} ${String(count).padStart(5)}  ${bar}`);
        }
        console.log();
      }

      // By server
      if (stats.byServer && Object.keys(stats.byServer).length > 0) {
        console.log('By Server');
        console.log('──────────────────────────────────────────');
        for (const [server, count] of Object.entries(stats.byServer)) {
          console.log(`  ${server.padEnd(20)} ${count}`);
        }
        console.log();
      }

      // Top tools
      if (stats.topTools && stats.topTools.length > 0) {
        console.log('Top Tools');
        console.log('──────────────────────────────────────────');
        for (const tool of stats.topTools.slice(0, 10)) {
          console.log(`  ${tool.name.padEnd(25)} ${tool.count}`);
        }
        console.log();
      }

    } catch (error) {
      console.error('Failed to get statistics:', error);
      process.exit(1);
    } finally {
      store?.close();
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

function percent(value: number, total: number): string {
  if (total === 0) return '0%';
  return `${Math.round((value / total) * 100)}%`;
}
