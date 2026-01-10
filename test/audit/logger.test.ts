import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuditLogger, type AuditEntry } from '../../src/audit/logger.js';
import type { RiskLevel } from '../../src/config/types.js';

describe('AuditLogger', () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger();
    vi.useFakeTimers();
  });

  describe('log', () => {
    it('creates entry with id and timestamp', async () => {
      await logger.log({
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      });

      const entries = await logger.query({});
      expect(entries).toHaveLength(1);
      expect(entries[0].id).toBeDefined();
      expect(entries[0].timestamp).toBeInstanceOf(Date);
    });

    it('generates unique ids for each entry', async () => {
      await logger.log({
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      });

      await logger.log({
        tool: 'write_file',
        riskLevel: 'write',
        decision: 'allowed',
      });

      const entries = await logger.query({});
      expect(entries[0].id).not.toBe(entries[1].id);
    });

    it('preserves all entry fields', async () => {
      await logger.log({
        server: 'filesystem',
        tool: 'write_file',
        args: { path: '/tmp/test.txt', content: 'hello' },
        riskLevel: 'write',
        decision: 'allowed',
        sessionId: 'session-123',
        duration: 150,
      });

      const entries = await logger.query({});
      expect(entries[0].server).toBe('filesystem');
      expect(entries[0].tool).toBe('write_file');
      expect(entries[0].args).toEqual({ path: '/tmp/test.txt', content: 'hello' });
      expect(entries[0].riskLevel).toBe('write');
      expect(entries[0].decision).toBe('allowed');
      expect(entries[0].sessionId).toBe('session-123');
      expect(entries[0].duration).toBe(150);
    });

    it('stores error information', async () => {
      await logger.log({
        tool: 'dangerous_tool',
        riskLevel: 'dangerous',
        decision: 'denied',
        error: 'Tool execution blocked by policy',
      });

      const entries = await logger.query({});
      expect(entries[0].error).toBe('Tool execution blocked by policy');
    });
  });

  describe('query', () => {
    beforeEach(async () => {
      // Set up test entries at different times
      vi.setSystemTime(new Date('2024-01-01T10:00:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      });

      vi.setSystemTime(new Date('2024-01-01T11:00:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'write_file',
        riskLevel: 'write',
        decision: 'allowed',
      });

      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      await logger.log({
        server: 'database',
        tool: 'execute_query',
        riskLevel: 'destructive',
        decision: 'denied',
      });

      vi.setSystemTime(new Date('2024-01-01T13:00:00Z'));
      await logger.log({
        server: 'database',
        tool: 'read_data',
        riskLevel: 'read',
        decision: 'allowed',
      });
    });

    it('returns all entries when no filters', async () => {
      const entries = await logger.query({});
      expect(entries).toHaveLength(4);
    });

    it('filters by since date', async () => {
      const entries = await logger.query({
        since: new Date('2024-01-01T11:30:00Z'),
      });

      expect(entries).toHaveLength(2);
      expect(entries.every(e => e.timestamp >= new Date('2024-01-01T11:30:00Z'))).toBe(true);
    });

    it('filters by until date', async () => {
      const entries = await logger.query({
        until: new Date('2024-01-01T11:30:00Z'),
      });

      expect(entries).toHaveLength(2);
      expect(entries.every(e => e.timestamp <= new Date('2024-01-01T11:30:00Z'))).toBe(true);
    });

    it('filters by since and until date range', async () => {
      const entries = await logger.query({
        since: new Date('2024-01-01T10:30:00Z'),
        until: new Date('2024-01-01T12:30:00Z'),
      });

      expect(entries).toHaveLength(2);
    });

    it('filters by server', async () => {
      const entries = await logger.query({ server: 'database' });

      expect(entries).toHaveLength(2);
      expect(entries.every(e => e.server === 'database')).toBe(true);
    });

    it('filters by tool', async () => {
      const entries = await logger.query({ tool: 'read_file' });

      expect(entries).toHaveLength(1);
      expect(entries[0].tool).toBe('read_file');
    });

    it('filters by risk level', async () => {
      const entries = await logger.query({ riskLevel: 'read' });

      expect(entries).toHaveLength(2);
      expect(entries.every(e => e.riskLevel === 'read')).toBe(true);
    });

    it('filters by decision allowed', async () => {
      const entries = await logger.query({ decision: 'allowed' });

      expect(entries).toHaveLength(3);
      expect(entries.every(e => e.decision === 'allowed')).toBe(true);
    });

    it('filters by decision denied', async () => {
      const entries = await logger.query({ decision: 'denied' });

      expect(entries).toHaveLength(1);
      expect(entries[0].decision).toBe('denied');
    });

    it('combines multiple filters', async () => {
      const entries = await logger.query({
        server: 'filesystem',
        decision: 'allowed',
      });

      expect(entries).toHaveLength(2);
      expect(entries.every(e => e.server === 'filesystem' && e.decision === 'allowed')).toBe(true);
    });

    it('sorts by timestamp descending (most recent first)', async () => {
      const entries = await logger.query({});

      expect(entries[0].timestamp.getTime()).toBeGreaterThan(entries[1].timestamp.getTime());
      expect(entries[1].timestamp.getTime()).toBeGreaterThan(entries[2].timestamp.getTime());
      expect(entries[2].timestamp.getTime()).toBeGreaterThan(entries[3].timestamp.getTime());
    });

    it('applies limit', async () => {
      const entries = await logger.query({ limit: 2 });

      expect(entries).toHaveLength(2);
      // Should be the two most recent
      expect(entries[0].tool).toBe('read_data');
      expect(entries[1].tool).toBe('execute_query');
    });

    it('returns empty array when no matches', async () => {
      const entries = await logger.query({
        server: 'nonexistent',
      });

      expect(entries).toHaveLength(0);
    });

    it('handles limit of 0 as no limit', async () => {
      const entries = await logger.query({ limit: 0 });

      expect(entries).toHaveLength(4);
    });

    it('handles limit larger than results', async () => {
      const entries = await logger.query({ limit: 100 });

      expect(entries).toHaveLength(4);
    });
  });

  describe('getStats', () => {
    beforeEach(async () => {
      vi.setSystemTime(new Date('2024-01-01T10:00:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      });

      vi.setSystemTime(new Date('2024-01-01T11:00:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
      });

      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'write_file',
        riskLevel: 'write',
        decision: 'allowed',
      });

      vi.setSystemTime(new Date('2024-01-01T13:00:00Z'));
      await logger.log({
        server: 'database',
        tool: 'execute_query',
        riskLevel: 'destructive',
        decision: 'denied',
      });

      vi.setSystemTime(new Date('2024-01-01T14:00:00Z'));
      await logger.log({
        server: 'database',
        tool: 'delete_table',
        riskLevel: 'dangerous',
        decision: 'denied',
      });
    });

    it('calculates total count', async () => {
      const stats = await logger.getStats();
      expect(stats.total).toBe(5);
    });

    it('calculates allowed count', async () => {
      const stats = await logger.getStats();
      expect(stats.allowed).toBe(3);
    });

    it('calculates denied count', async () => {
      const stats = await logger.getStats();
      expect(stats.denied).toBe(2);
    });

    it('groups by risk level', async () => {
      const stats = await logger.getStats();
      expect(stats.byRiskLevel.read).toBe(2);
      expect(stats.byRiskLevel.write).toBe(1);
      expect(stats.byRiskLevel.destructive).toBe(1);
      expect(stats.byRiskLevel.dangerous).toBe(1);
    });

    it('groups by server', async () => {
      const stats = await logger.getStats();
      expect(stats.byServer.filesystem).toBe(3);
      expect(stats.byServer.database).toBe(2);
    });

    it('identifies top tools', async () => {
      const stats = await logger.getStats();
      expect(stats.topTools[0]).toEqual({ name: 'read_file', count: 2 });
      expect(stats.topTools.length).toBeGreaterThanOrEqual(3);
    });

    it('sorts top tools by count descending', async () => {
      const stats = await logger.getStats();
      for (let i = 0; i < stats.topTools.length - 1; i++) {
        expect(stats.topTools[i].count).toBeGreaterThanOrEqual(stats.topTools[i + 1].count);
      }
    });

    it('limits top tools to 10', async () => {
      // Add many different tools
      for (let i = 0; i < 15; i++) {
        await logger.log({
          tool: `tool_${i}`,
          riskLevel: 'safe',
          decision: 'allowed',
        });
      }

      const stats = await logger.getStats();
      expect(stats.topTools.length).toBeLessThanOrEqual(10);
    });

    it('filters by since date', async () => {
      const stats = await logger.getStats(new Date('2024-01-01T12:30:00Z'));
      expect(stats.total).toBe(2);
      expect(stats.allowed).toBe(0);
      expect(stats.denied).toBe(2);
    });

    it('handles empty log', async () => {
      const emptyLogger = new AuditLogger();
      const stats = await emptyLogger.getStats();

      expect(stats.total).toBe(0);
      expect(stats.allowed).toBe(0);
      expect(stats.denied).toBe(0);
      expect(Object.keys(stats.byRiskLevel).length).toBe(0);
      expect(Object.keys(stats.byServer).length).toBe(0);
      expect(stats.topTools.length).toBe(0);
    });

    it('handles entries without server', async () => {
      const newLogger = new AuditLogger();
      await newLogger.log({
        tool: 'test_tool',
        riskLevel: 'safe',
        decision: 'allowed',
        // No server field
      });

      const stats = await newLogger.getStats();
      expect(Object.keys(stats.byServer).length).toBe(0);
    });
  });

  describe('export', () => {
    let entries: AuditEntry[];

    beforeEach(async () => {
      vi.setSystemTime(new Date('2024-01-15T10:30:00Z'));
      await logger.log({
        server: 'filesystem',
        tool: 'read_file',
        riskLevel: 'read',
        decision: 'allowed',
        duration: 50,
      });

      vi.setSystemTime(new Date('2024-01-15T11:30:00Z'));
      await logger.log({
        server: 'database',
        tool: 'write_data',
        riskLevel: 'write',
        decision: 'denied',
        duration: 100,
      });

      entries = await logger.query({});
    });

    describe('JSON format', () => {
      it('exports entries as JSON', async () => {
        const json = await logger.export(entries, 'json');
        const parsed = JSON.parse(json);

        expect(parsed).toHaveLength(2);
        expect(parsed[0]).toHaveProperty('id');
        expect(parsed[0]).toHaveProperty('timestamp');
        expect(parsed[0]).toHaveProperty('tool');
      });

      it('formats JSON with indentation', async () => {
        const json = await logger.export(entries, 'json');
        expect(json).toContain('\n');
        expect(json).toContain('  ');
      });

      it('exports empty array as valid JSON', async () => {
        const json = await logger.export([], 'json');
        const parsed = JSON.parse(json);
        expect(parsed).toEqual([]);
      });
    });

    describe('CSV format', () => {
      it('exports entries as CSV with headers', async () => {
        const csv = await logger.export(entries, 'csv');
        const lines = csv.split('\n');

        expect(lines[0]).toBe('id,timestamp,server,tool,risk_level,decision,duration');
      });

      it('exports data rows', async () => {
        const csv = await logger.export(entries, 'csv');
        const lines = csv.split('\n');

        expect(lines.length).toBe(3); // Header + 2 data rows
      });

      it('quotes all values', async () => {
        const csv = await logger.export(entries, 'csv');
        const dataLine = csv.split('\n')[1];

        expect(dataLine).toMatch(/^"[^"]+","[^"]+","[^"]+","[^"]+","[^"]+","[^"]+","[^"]*"$/);
      });

      it('handles empty server field', async () => {
        const newLogger = new AuditLogger();
        await newLogger.log({
          tool: 'test_tool',
          riskLevel: 'safe',
          decision: 'allowed',
        });

        const newEntries = await newLogger.query({});
        const csv = await newLogger.export(newEntries, 'csv');
        const lines = csv.split('\n');

        // Server field should be empty string
        expect(lines[1]).toContain(',"",');
      });

      it('handles empty duration field', async () => {
        const newLogger = new AuditLogger();
        await newLogger.log({
          tool: 'test_tool',
          riskLevel: 'safe',
          decision: 'allowed',
        });

        const newEntries = await newLogger.query({});
        const csv = await newLogger.export(newEntries, 'csv');
        const lines = csv.split('\n');

        // Duration should be empty string at end
        expect(lines[1]).toMatch(/,""$/);
      });
    });

    describe('CEF format', () => {
      it('exports entries as CEF', async () => {
        const cef = await logger.export(entries, 'cef');
        const lines = cef.split('\n');

        expect(lines.length).toBe(2);
        expect(lines[0]).toMatch(/^CEF:0\|DotsetLabs\|Overwatch\|1\.0\|/);
      });

      it('includes tool in extension', async () => {
        const cef = await logger.export(entries, 'cef');

        expect(cef).toContain('cs1=read_file');
        expect(cef).toContain('cs1Label=Tool');
      });

      it('includes server in extension when present', async () => {
        const cef = await logger.export(entries, 'cef');

        expect(cef).toContain('cs2=filesystem');
        expect(cef).toContain('cs2Label=Server');
      });

      it('includes outcome', async () => {
        const cef = await logger.export(entries, 'cef');

        expect(cef).toContain('outcome=allowed');
        expect(cef).toContain('outcome=denied');
      });

      it('maps risk levels to CEF severity', async () => {
        // Add entries with all risk levels
        const newLogger = new AuditLogger();

        const riskLevels: RiskLevel[] = ['safe', 'read', 'write', 'destructive', 'dangerous'];
        for (const risk of riskLevels) {
          await newLogger.log({
            tool: `${risk}_tool`,
            riskLevel: risk,
            decision: 'allowed',
          });
        }

        const newEntries = await newLogger.query({});
        const cef = await newLogger.export(newEntries, 'cef');

        // CEF format: CEF:0|Vendor|Product|Version|EventID|EventName|Severity|Extension
        // Check severity mapping: dangerous=10, destructive=8, write=5, read=3, safe=1
        expect(cef).toMatch(/\|dangerous\|MCP Tool Call\|10\|.*cs1=dangerous_tool/);
        expect(cef).toMatch(/\|destructive\|MCP Tool Call\|8\|.*cs1=destructive_tool/);
        expect(cef).toMatch(/\|write\|MCP Tool Call\|5\|.*cs1=write_tool/);
        expect(cef).toMatch(/\|read\|MCP Tool Call\|3\|.*cs1=read_tool/);
        expect(cef).toMatch(/\|safe\|MCP Tool Call\|1\|.*cs1=safe_tool/);
      });
    });

    describe('unknown format', () => {
      it('throws error for unknown format', async () => {
        await expect(
          logger.export(entries, 'xml' as 'json' | 'csv' | 'cef')
        ).rejects.toThrow('Unknown export format: xml');
      });
    });
  });

  describe('tail', () => {
    it('notifies callback when new entry is logged', async () => {
      const callback = vi.fn();

      // Start tail in background (don't await - it blocks forever)
      logger.tail(callback);

      // Log an entry
      await logger.log({
        tool: 'test_tool',
        riskLevel: 'safe',
        decision: 'allowed',
      });

      expect(callback).toHaveBeenCalledTimes(1);
      expect(callback).toHaveBeenCalledWith(
        expect.objectContaining({
          tool: 'test_tool',
          riskLevel: 'safe',
          decision: 'allowed',
        })
      );
    });

    it('notifies multiple callbacks', async () => {
      const callback1 = vi.fn();
      const callback2 = vi.fn();

      logger.tail(callback1);
      logger.tail(callback2);

      await logger.log({
        tool: 'test_tool',
        riskLevel: 'safe',
        decision: 'allowed',
      });

      expect(callback1).toHaveBeenCalledTimes(1);
      expect(callback2).toHaveBeenCalledTimes(1);
    });

    it('notifies callback for each new entry', async () => {
      const callback = vi.fn();

      logger.tail(callback);

      await logger.log({
        tool: 'tool1',
        riskLevel: 'safe',
        decision: 'allowed',
      });

      await logger.log({
        tool: 'tool2',
        riskLevel: 'read',
        decision: 'allowed',
      });

      await logger.log({
        tool: 'tool3',
        riskLevel: 'write',
        decision: 'denied',
      });

      expect(callback).toHaveBeenCalledTimes(3);
    });

    it('passes complete entry to callback', async () => {
      const callback = vi.fn();

      logger.tail(callback);

      await logger.log({
        server: 'testserver',
        tool: 'test_tool',
        args: { key: 'value' },
        riskLevel: 'safe',
        decision: 'allowed',
        sessionId: 'sess-123',
        duration: 50,
      });

      const entry = callback.mock.calls[0][0] as AuditEntry;
      expect(entry.id).toBeDefined();
      expect(entry.timestamp).toBeInstanceOf(Date);
      expect(entry.server).toBe('testserver');
      expect(entry.tool).toBe('test_tool');
      expect(entry.args).toEqual({ key: 'value' });
      expect(entry.riskLevel).toBe('safe');
      expect(entry.decision).toBe('allowed');
      expect(entry.sessionId).toBe('sess-123');
      expect(entry.duration).toBe(50);
    });
  });

  describe('edge cases', () => {
    it('handles all risk levels', async () => {
      const riskLevels: RiskLevel[] = ['safe', 'read', 'write', 'destructive', 'dangerous'];

      for (const risk of riskLevels) {
        await logger.log({
          tool: `${risk}_tool`,
          riskLevel: risk,
          decision: 'allowed',
        });
      }

      const entries = await logger.query({});
      expect(entries).toHaveLength(5);
    });

    it('handles args with various data types', async () => {
      await logger.log({
        tool: 'complex_tool',
        args: {
          string: 'value',
          number: 42,
          boolean: true,
          array: [1, 2, 3],
          nested: { a: { b: 'c' } },
          nullValue: null,
        },
        riskLevel: 'safe',
        decision: 'allowed',
      });

      const entries = await logger.query({});
      expect(entries[0].args).toEqual({
        string: 'value',
        number: 42,
        boolean: true,
        array: [1, 2, 3],
        nested: { a: { b: 'c' } },
        nullValue: null,
      });
    });

    it('handles concurrent logging', async () => {
      const promises = [];
      for (let i = 0; i < 100; i++) {
        promises.push(logger.log({
          tool: `tool_${i}`,
          riskLevel: 'safe',
          decision: 'allowed',
        }));
      }

      await Promise.all(promises);

      const entries = await logger.query({});
      expect(entries).toHaveLength(100);
    });

    it('handles empty args object', async () => {
      await logger.log({
        tool: 'test_tool',
        args: {},
        riskLevel: 'safe',
        decision: 'allowed',
      });

      const entries = await logger.query({});
      expect(entries[0].args).toEqual({});
    });

    it('handles very long tool names', async () => {
      const longName = 'a'.repeat(1000);
      await logger.log({
        tool: longName,
        riskLevel: 'safe',
        decision: 'allowed',
      });

      const entries = await logger.query({});
      expect(entries[0].tool).toBe(longName);
    });
  });
});
