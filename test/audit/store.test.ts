import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuditStore } from '../../src/audit/store.js';
import type { AuditEntry } from '../../src/audit/logger.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('AuditStore', () => {
  let store: AuditStore;
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `test-audit-${Date.now()}.db`);
    store = new AuditStore(dbPath);
  });

  afterEach(() => {
    store.close();
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
  });

  function createEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
    return {
      id: `entry-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: new Date(),
      tool: 'read_file',
      riskLevel: 'read',
      decision: 'allowed',
      ...overrides,
    };
  }

  describe('save and query', () => {
    it('saves and retrieves an entry', () => {
      const entry = createEntry({
        id: 'test-entry-1',
        server: 'filesystem',
        args: { path: '/test/file.txt' },
      });

      store.save(entry);
      const results = store.query({ limit: 10 });

      expect(results.length).toBe(1);
      expect(results[0].id).toBe('test-entry-1');
      expect(results[0].server).toBe('filesystem');
      expect(results[0].args).toEqual({ path: '/test/file.txt' });
    });

    it('saves entry with all fields', () => {
      const entry = createEntry({
        id: 'full-entry',
        server: 'database',
        tool: 'execute_sql',
        args: { query: 'SELECT 1' },
        riskLevel: 'write',
        decision: 'allowed',
        sessionId: 'session-123',
        duration: 150,
        error: undefined,
      });

      store.save(entry);
      const results = store.query({ limit: 1 });

      expect(results[0].sessionId).toBe('session-123');
      expect(results[0].duration).toBe(150);
    });

    it('saves entry with error', () => {
      const entry = createEntry({
        id: 'error-entry',
        decision: 'denied',
        error: 'Access denied by policy',
      });

      store.save(entry);
      const results = store.query({ limit: 1 });

      expect(results[0].error).toBe('Access denied by policy');
    });
  });

  describe('query filters', () => {
    beforeEach(() => {
      // Populate with test data
      const now = Date.now();

      store.save(createEntry({
        id: 'entry-1',
        timestamp: new Date(now - 3600000), // 1 hour ago
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      }));

      store.save(createEntry({
        id: 'entry-2',
        timestamp: new Date(now - 1800000), // 30 min ago
        server: 'filesystem',
        tool: 'write_file',
        riskLevel: 'write',
        decision: 'denied',
      }));

      store.save(createEntry({
        id: 'entry-3',
        timestamp: new Date(now - 900000), // 15 min ago
        server: 'database',
        tool: 'execute_sql',
        riskLevel: 'dangerous',
        decision: 'denied',
      }));

      store.save(createEntry({
        id: 'entry-4',
        timestamp: new Date(now),
        server: 'database',
        tool: 'execute_sql',
        riskLevel: 'read',
        decision: 'allowed',
      }));
    });

    it('filters by server', () => {
      const results = store.query({ server: 'filesystem' });
      expect(results.length).toBe(2);
      expect(results.every(r => r.server === 'filesystem')).toBe(true);
    });

    it('filters by tool', () => {
      const results = store.query({ tool: 'execute_sql' });
      expect(results.length).toBe(2);
      expect(results.every(r => r.tool === 'execute_sql')).toBe(true);
    });

    it('filters by risk level', () => {
      const results = store.query({ riskLevel: 'read' });
      expect(results.length).toBe(2);
      expect(results.every(r => r.riskLevel === 'read')).toBe(true);
    });

    it('filters by decision', () => {
      const results = store.query({ decision: 'denied' });
      expect(results.length).toBe(2);
      expect(results.every(r => r.decision === 'denied')).toBe(true);
    });

    it('filters by time range (since)', () => {
      const since = new Date(Date.now() - 1000000); // ~16 min ago
      const results = store.query({ since });
      expect(results.length).toBe(2); // entry-3 and entry-4
    });

    it('filters by time range (until)', () => {
      const until = new Date(Date.now() - 1000000); // ~16 min ago
      const results = store.query({ until });
      expect(results.length).toBe(2); // entry-1 and entry-2
    });

    it('filters by time range (since and until)', () => {
      const since = new Date(Date.now() - 2000000);
      const until = new Date(Date.now() - 1000000);
      const results = store.query({ since, until });
      expect(results.length).toBe(1); // entry-2
    });

    it('applies limit', () => {
      const results = store.query({ limit: 2 });
      expect(results.length).toBe(2);
    });

    it('orders by timestamp descending', () => {
      const results = store.query({});
      expect(results[0].id).toBe('entry-4');
      expect(results[3].id).toBe('entry-1');
    });

    it('combines multiple filters', () => {
      const results = store.query({
        server: 'database',
        decision: 'denied',
      });
      expect(results.length).toBe(1);
      expect(results[0].id).toBe('entry-3');
    });
  });

  describe('getStats', () => {
    beforeEach(() => {
      // Populate with test data
      store.save(createEntry({
        id: 's1',
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      }));
      store.save(createEntry({
        id: 's2',
        server: 'filesystem',
        tool: 'write_file',
        riskLevel: 'write',
        decision: 'allowed',
      }));
      store.save(createEntry({
        id: 's3',
        server: 'database',
        tool: 'execute_sql',
        riskLevel: 'write',
        decision: 'denied',
      }));
      store.save(createEntry({
        id: 's4',
        server: 'database',
        tool: 'execute_sql',
        riskLevel: 'dangerous',
        decision: 'denied',
      }));
      store.save(createEntry({
        id: 's5',
        server: 'database',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      }));
    });

    it('calculates total count', () => {
      const stats = store.getStats();
      expect(stats.total).toBe(5);
    });

    it('calculates allowed count', () => {
      const stats = store.getStats();
      expect(stats.allowed).toBe(3);
    });

    it('calculates denied count', () => {
      const stats = store.getStats();
      expect(stats.denied).toBe(2);
    });

    it('groups by risk level', () => {
      const stats = store.getStats();
      expect(stats.byRiskLevel.read).toBe(2);
      expect(stats.byRiskLevel.write).toBe(2);
      expect(stats.byRiskLevel.dangerous).toBe(1);
    });

    it('groups by server', () => {
      const stats = store.getStats();
      expect(stats.byServer.filesystem).toBe(2);
      expect(stats.byServer.database).toBe(3);
    });

    it('calculates top tools', () => {
      const stats = store.getStats();
      expect(stats.topTools.length).toBeGreaterThan(0);

      const sqlTool = stats.topTools.find(t => t.name === 'execute_sql');
      expect(sqlTool?.count).toBe(2);

      const readTool = stats.topTools.find(t => t.name === 'read_file');
      expect(readTool?.count).toBe(2);
    });

    it('filters stats by since date', () => {
      // Add an old entry
      const oldEntry = createEntry({
        id: 'old-entry',
        riskLevel: 'safe',
        decision: 'allowed',
      });
      oldEntry.timestamp = new Date(Date.now() - 86400000); // 24 hours ago
      store.save(oldEntry);

      const stats = store.getStats(new Date(Date.now() - 3600000)); // Last hour
      expect(stats.total).toBe(5); // Should not include old entry
    });
  });

  describe('delete', () => {
    it('deletes an entry by id', () => {
      store.save(createEntry({ id: 'to-delete' }));
      expect(store.query({ limit: 10 }).length).toBe(1);

      const deleted = store.delete('to-delete');
      expect(deleted).toBe(true);
      expect(store.query({ limit: 10 }).length).toBe(0);
    });

    it('returns false when entry does not exist', () => {
      const deleted = store.delete('non-existent');
      expect(deleted).toBe(false);
    });
  });

  describe('prune', () => {
    it('removes entries before date', () => {
      const now = Date.now();

      store.save(createEntry({
        id: 'old-1',
        timestamp: new Date(now - 86400000 * 2), // 2 days ago
      }));
      store.save(createEntry({
        id: 'old-2',
        timestamp: new Date(now - 86400000 * 3), // 3 days ago
      }));
      store.save(createEntry({
        id: 'recent',
        timestamp: new Date(now),
      }));

      const pruned = store.prune(new Date(now - 86400000)); // Prune older than 1 day
      expect(pruned).toBe(2);
      expect(store.query({ limit: 10 }).length).toBe(1);
    });
  });

  describe('close', () => {
    it('closes the database connection', () => {
      store.save(createEntry({ id: 'test' }));
      store.close();

      // Attempting to query after close should throw
      expect(() => store.query({})).toThrow();
    });
  });
});
