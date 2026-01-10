import { Command } from 'commander';
import { SessionManager } from '../../session/manager.js';

export const sessionsCommand = new Command('sessions')
  .description('Manage approval sessions');

sessionsCommand
  .command('list')
  .alias('ls')
  .description('List active sessions')
  .option('--json', 'Output as JSON')
  .action(async (options) => {
    try {
      const manager = new SessionManager();
      const sessions = await manager.list();

      if (options.json) {
        console.log(JSON.stringify(sessions, null, 2));
        return;
      }

      if (sessions.length === 0) {
        console.log('No active sessions');
        return;
      }

      console.log(`Active sessions (${sessions.length}):\n`);

      for (const session of sessions) {
        const expiresIn = Math.round((session.expiresAt.getTime() - Date.now()) / 1000 / 60);
        console.log(`  ${session.id}`);
        console.log(`    Scope: ${session.scope} (${session.pattern})`);
        console.log(`    Server: ${session.server || 'any'}`);
        console.log(`    Expires: ${expiresIn > 0 ? `in ${expiresIn} minutes` : 'expired'}`);
        console.log();
      }
    } catch (error) {
      console.error('Failed to list sessions:', error);
      process.exit(1);
    }
  });

sessionsCommand
  .command('revoke [id]')
  .description('Revoke a session (or all sessions if no ID given)')
  .option('--all', 'Revoke all sessions')
  .action(async (id: string | undefined, options) => {
    try {
      const manager = new SessionManager();

      if (options.all || !id) {
        const count = await manager.revokeAll();
        console.log(`Revoked ${count} session(s)`);
      } else {
        const revoked = await manager.revoke(id);
        if (revoked) {
          console.log(`Revoked session: ${id}`);
        } else {
          console.error(`Session not found: ${id}`);
          process.exit(1);
        }
      }
    } catch (error) {
      console.error('Failed to revoke session:', error);
      process.exit(1);
    }
  });

// Default action (list)
sessionsCommand.action(async () => {
  await sessionsCommand.commands.find(c => c.name() === 'list')?.parseAsync([]);
});
