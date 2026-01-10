import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SessionManager } from '../../src/session/manager.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('SessionManager', () => {
  let manager: SessionManager;
  let dbPath: string;
  let testId = 0;

  beforeEach(() => {
    testId++;
    dbPath = path.join(os.tmpdir(), `test-sessions-${Date.now()}-${testId}-${Math.random().toString(36).slice(2)}.db`);
    manager = new SessionManager({
      dbPath,
      enableBackgroundCleanup: false, // Disable for tests
    });
  });

  afterEach(async () => {
    await manager.close();
    // Small delay to ensure database is released
    await new Promise(resolve => setTimeout(resolve, 10));
    try {
      if (fs.existsSync(dbPath)) {
        fs.unlinkSync(dbPath);
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('create and check', () => {
    it('creates a session with legacy API', async () => {
      const session = await manager.create('exact', 'read_file:/test', '5min');

      expect(session.id).toBeDefined();
      expect(session.scope).toBe('exact');
      expect(session.pattern).toBe('read_file:/test');
      expect(session.expiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('creates a session with options API', async () => {
      const session = await manager.create({
        scope: 'tool',
        pattern: 'read_*',
        duration: '15min',
        server: 'filesystem',
        approver: 'user@example.com',
        toolName: 'read_file',
        riskLevel: 'read',
        reason: 'Needed for file browsing',
      });

      expect(session.scope).toBe('tool');
      expect(session.server).toBe('filesystem');
      expect(session.audit).toBeDefined();
      expect(session.audit?.approver).toBe('user@example.com');
      expect(session.audit?.toolName).toBe('read_file');
      expect(session.audit?.riskLevel).toBe('read');
    });

    it('checks exact match sessions', async () => {
      await manager.create('exact', 'read_file:/path/to/file', '5min');

      const match = await manager.check('read_file:/path/to/file');
      expect(match).not.toBeNull();

      const noMatch = await manager.check('read_file:/different/path');
      expect(noMatch).toBeNull();
    });

    it('checks tool pattern match sessions', async () => {
      await manager.create('tool', 'read_*', '5min');

      const match = await manager.check('read_file');
      expect(match).not.toBeNull();

      const noMatch = await manager.check('write_file');
      expect(noMatch).toBeNull();
    });

    it('checks server scope sessions', async () => {
      await manager.create('server', '*', '5min', 'filesystem');

      const match = await manager.check('any_tool', 'filesystem');
      expect(match).not.toBeNull();

      const noMatch = await manager.check('any_tool', 'other-server');
      expect(noMatch).toBeNull();
    });
  });

  describe('audit trail (O-H12)', () => {
    it('records usage count on check', async () => {
      const session = await manager.create({
        scope: 'exact',
        pattern: 'test_tool',
        duration: '5min',
        approver: 'tester',
        toolName: 'test_tool',
      });

      // Check multiple times
      await manager.check('test_tool');
      await manager.check('test_tool');
      await manager.check('test_tool');

      const updated = await manager.get(session.id);
      expect(updated?.audit?.useCount).toBe(3);
    });

    it('records last used time on check', async () => {
      const session = await manager.create({
        scope: 'exact',
        pattern: 'test_tool',
        duration: '5min',
        approver: 'tester',
        toolName: 'test_tool',
      });

      const beforeCheck = Date.now();
      await manager.check('test_tool');
      const afterCheck = Date.now();

      const updated = await manager.get(session.id);
      expect(updated?.audit?.lastUsedAt).toBeDefined();
      expect(updated!.audit!.lastUsedAt!.getTime()).toBeGreaterThanOrEqual(beforeCheck);
      expect(updated!.audit!.lastUsedAt!.getTime()).toBeLessThanOrEqual(afterCheck);
    });

    it('stores tool arguments in audit', async () => {
      const args = { path: '/etc/passwd', mode: 'read' };
      const session = await manager.create({
        scope: 'exact',
        pattern: 'read_file',
        duration: '5min',
        approver: 'admin',
        toolName: 'read_file',
        toolArgs: args,
      });

      const retrieved = await manager.get(session.id);
      expect(retrieved?.audit?.toolArgs).toBe(JSON.stringify(args));
    });
  });

  describe('revocation (O-H13)', () => {
    it('revokes session by ID', async () => {
      const session = await manager.create('exact', 'tool:/path', '5min');

      const revoked = await manager.revoke(session.id, 'admin', 'Suspicious activity');
      expect(revoked).toBe(true);

      // Session should not match after revocation
      const match = await manager.check('tool:/path');
      expect(match).toBeNull();
    });

    it('revokes sessions by pattern', async () => {
      await manager.create('tool', 'read_*', '5min', 'fs1');
      await manager.create('tool', 'read_*', '5min', 'fs2');
      await manager.create('tool', 'write_*', '5min');

      const count = await manager.revokeByPattern('read_*', 'admin', 'Policy change');
      expect(count).toBe(2);

      // read_* sessions should not match
      expect(await manager.check('read_file')).toBeNull();

      // write_* session should still work
      expect(await manager.check('write_file')).not.toBeNull();
    });

    it('revokes sessions by server', async () => {
      await manager.create('tool', 'tool1', '5min', 'compromised-server');
      await manager.create('tool', 'tool2', '5min', 'compromised-server');
      await manager.create('tool', 'tool3', '5min', 'safe-server');

      const count = await manager.revokeByServer('compromised-server', 'admin', 'Server compromised');
      expect(count).toBe(2);

      // Sessions for compromised server should not match
      expect(await manager.check('tool1', 'compromised-server')).toBeNull();

      // Sessions for safe server should still work
      expect(await manager.check('tool3', 'safe-server')).not.toBeNull();
    });

    it('revokes all sessions', async () => {
      await manager.create('exact', 'tool1', '5min');
      await manager.create('exact', 'tool2', '5min');
      await manager.create('exact', 'tool3', '5min');

      const count = await manager.revokeAll('admin', 'System reset');
      expect(count).toBe(3);

      expect((await manager.list()).length).toBe(0);
    });

    it('stores revocation info in audit', async () => {
      const session = await manager.create({
        scope: 'exact',
        pattern: 'tool',
        duration: '5min',
        approver: 'user',
        toolName: 'tool',
      });

      await manager.revoke(session.id, 'security-team', 'Emergency revocation');

      const retrieved = await manager.get(session.id);
      expect(retrieved?.audit?.revocation).toBeDefined();
      expect(retrieved?.audit?.revocation?.revokedBy).toBe('security-team');
      expect(retrieved?.audit?.revocation?.reason).toBe('Emergency revocation');
    });
  });

  describe('background cleanup (O-H14)', () => {
    it('prunes expired sessions via manual cleanup', async () => {
      // Create expired session (backdate)
      const expiredSession = {
        id: 'expired-1',
        scope: 'exact' as const,
        pattern: 'old_tool',
        createdAt: new Date(Date.now() - 600000),
        expiresAt: new Date(Date.now() - 300000),
      };

      // Access store directly for test setup
      const store = (manager as unknown as { store: { save: (s: typeof expiredSession) => void } }).store;
      store.save(expiredSession);

      // Create valid session
      await manager.create('exact', 'new_tool', '5min');

      const pruned = await manager.cleanup();
      expect(pruned).toBe(1);

      const sessions = await manager.list({ activeOnly: false });
      expect(sessions.length).toBe(1);
      expect(sessions[0].pattern).toBe('new_tool');
    });

    it('updates lastCleanup time after cleanup', async () => {
      const beforeCleanup = Date.now();
      await manager.cleanup();
      const afterCleanup = Date.now();

      const stats = await manager.getStats();
      expect(stats.lastCleanup).toBeDefined();
      expect(stats.lastCleanup!.getTime()).toBeGreaterThanOrEqual(beforeCleanup);
      expect(stats.lastCleanup!.getTime()).toBeLessThanOrEqual(afterCleanup);
    });

    it('runs background cleanup on interval', async () => {
      // Create manager with short cleanup interval
      const bgManager = new SessionManager({
        dbPath: path.join(os.tmpdir(), `test-bg-cleanup-${Date.now()}.db`),
        enableBackgroundCleanup: true,
        cleanupIntervalMs: 50, // 50ms for testing
      });

      try {
        // Wait for at least one cleanup cycle
        await new Promise(resolve => setTimeout(resolve, 100));

        const stats = await bgManager.getStats();
        expect(stats.lastCleanup).toBeDefined();
      } finally {
        await bgManager.close();
      }
    });
  });

  describe('statistics', () => {
    it('returns session statistics', async () => {
      await manager.create({
        scope: 'exact',
        pattern: 'tool1',
        duration: '5min',
        server: 'server1',
        approver: 'user1',
        toolName: 'tool1',
      });

      await manager.create({
        scope: 'tool',
        pattern: 'tool*',
        duration: '5min',
        server: 'server1',
        approver: 'user2',
        toolName: 'tool2',
      });

      await manager.create({
        scope: 'server',
        pattern: '*',
        duration: '5min',
        server: 'server2',
        approver: 'user1',
        toolName: 'all-tools',
      });

      const stats = await manager.getStats();

      expect(stats.totalSessions).toBe(3);
      expect(stats.activeSessions).toBe(3);
      expect(stats.byScope['exact']).toBe(1);
      expect(stats.byScope['tool']).toBe(1);
      expect(stats.byScope['server']).toBe(1);
      expect(stats.byServer['server1']).toBe(2);
      expect(stats.byServer['server2']).toBe(1);
    });

    it('counts approvals correctly', async () => {
      const session = await manager.create({
        scope: 'tool',
        pattern: 'read_*',
        duration: '5min',
        approver: 'admin',
        toolName: 'read_file',
      });

      // Use the session multiple times
      await manager.check('read_file');
      await manager.check('read_config');
      await manager.check('read_data');

      const stats = await manager.getStats();
      expect(stats.totalApprovals).toBe(3);
    });
  });

  describe('list with query', () => {
    beforeEach(async () => {
      await manager.create({ scope: 'exact', pattern: 'tool1', duration: '5min', server: 'fs' });
      await manager.create({ scope: 'tool', pattern: 'read_*', duration: '5min', server: 'fs' });
      await manager.create({ scope: 'server', pattern: '*', duration: '5min', server: 'http' });
    });

    it('filters by server', async () => {
      const sessions = await manager.list({ server: 'fs' });
      expect(sessions.length).toBe(2);
    });

    it('filters by scope', async () => {
      const sessions = await manager.list({ scope: 'exact' });
      expect(sessions.length).toBe(1);
      expect(sessions[0].pattern).toBe('tool1');
    });

    it('limits results', async () => {
      const sessions = await manager.list({ limit: 2 });
      expect(sessions.length).toBe(2);
    });
  });

  describe('findByPattern', () => {
    it('finds sessions matching pattern', async () => {
      await manager.create('tool', 'read_*', '5min');
      await manager.create('tool', 'read_*', '5min', 'fs-server');
      await manager.create('tool', 'write_*', '5min');

      const matches = await manager.findByPattern('read_*');
      expect(matches.length).toBe(2);
    });

    it('filters by server', async () => {
      await manager.create('tool', 'read_*', '5min');
      await manager.create('tool', 'read_*', '5min', 'fs-server');

      const matches = await manager.findByPattern('read_*', 'fs-server');
      expect(matches.length).toBe(2); // Both match (null server matches all)
    });
  });

  describe('duration handling', () => {
    it('handles once duration', async () => {
      const session = await manager.create('exact', 'tool', 'once');
      expect(session.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
    });

    it('handles 5min duration', async () => {
      const now = Date.now();
      const session = await manager.create('exact', 'tool', '5min');
      expect(session.expiresAt.getTime()).toBeCloseTo(now + 5 * 60 * 1000, -2);
    });

    it('handles 15min duration', async () => {
      const now = Date.now();
      const session = await manager.create('exact', 'tool', '15min');
      expect(session.expiresAt.getTime()).toBeCloseTo(now + 15 * 60 * 1000, -2);
    });

    it('handles session duration', async () => {
      const now = Date.now();
      const session = await manager.create('exact', 'tool', 'session');
      expect(session.expiresAt.getTime()).toBeCloseTo(now + 24 * 60 * 60 * 1000, -2);
    });

    it('handles numeric duration in milliseconds', async () => {
      const now = Date.now();
      const session = await manager.create('exact', 'tool', 120000); // 2 minutes
      expect(session.expiresAt.getTime()).toBeCloseTo(now + 120000, -2);
    });
  });
});
