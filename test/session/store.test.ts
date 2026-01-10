import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { SessionStore } from '../../src/session/store.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('SessionStore', () => {
  let store: SessionStore;
  let dbPath: string;

  beforeEach(() => {
    // Create a temporary database file
    dbPath = path.join(os.tmpdir(), `test-sessions-${Date.now()}.db`);
    store = new SessionStore(dbPath);
  });

  afterEach(() => {
    store.close();
    // Clean up the temporary database
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
  });

  describe('save and get', () => {
    it('saves and retrieves a session', () => {
      const session = {
        id: 'test-session-1',
        scope: 'exact' as const,
        pattern: 'read_file:/path/to/file',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000), // 5 minutes
      };

      store.save(session);
      const retrieved = store.get('test-session-1');

      expect(retrieved).not.toBeNull();
      expect(retrieved?.id).toBe(session.id);
      expect(retrieved?.scope).toBe(session.scope);
      expect(retrieved?.pattern).toBe(session.pattern);
    });

    it('returns null for non-existent session', () => {
      const retrieved = store.get('non-existent');
      expect(retrieved).toBeNull();
    });

    it('saves session with server', () => {
      const session = {
        id: 'test-session-2',
        scope: 'tool' as const,
        pattern: 'read_file',
        server: 'filesystem',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      };

      store.save(session);
      const retrieved = store.get('test-session-2');

      expect(retrieved?.server).toBe('filesystem');
    });

    it('updates existing session', () => {
      const session = {
        id: 'test-session-3',
        scope: 'exact' as const,
        pattern: 'write_file:/original',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      };

      store.save(session);

      // Update the session
      session.pattern = 'write_file:/updated';
      store.save(session);

      const retrieved = store.get('test-session-3');
      expect(retrieved?.pattern).toBe('write_file:/updated');
    });
  });

  describe('list', () => {
    it('lists only non-expired sessions', () => {
      // Create an expired session
      const expiredSession = {
        id: 'expired-session',
        scope: 'exact' as const,
        pattern: 'old_tool:/old/path',
        createdAt: new Date(Date.now() - 600000),
        expiresAt: new Date(Date.now() - 300000), // Expired 5 minutes ago
      };

      // Create a valid session
      const validSession = {
        id: 'valid-session',
        scope: 'tool' as const,
        pattern: 'read_file',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      };

      store.save(expiredSession);
      store.save(validSession);

      const sessions = store.list();

      expect(sessions.length).toBe(1);
      expect(sessions[0].id).toBe('valid-session');
    });

    it('returns empty array when no valid sessions', () => {
      const expiredSession = {
        id: 'expired-session',
        scope: 'exact' as const,
        pattern: 'tool:/path',
        createdAt: new Date(Date.now() - 600000),
        expiresAt: new Date(Date.now() - 300000),
      };

      store.save(expiredSession);

      const sessions = store.list();
      expect(sessions.length).toBe(0);
    });
  });

  describe('delete', () => {
    it('deletes a session', () => {
      const session = {
        id: 'to-delete',
        scope: 'exact' as const,
        pattern: 'delete_file:/path',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      };

      store.save(session);
      expect(store.get('to-delete')).not.toBeNull();

      const deleted = store.delete('to-delete');
      expect(deleted).toBe(true);
      expect(store.get('to-delete')).toBeNull();
    });

    it('returns false when deleting non-existent session', () => {
      const deleted = store.delete('non-existent');
      expect(deleted).toBe(false);
    });
  });

  describe('deleteAll', () => {
    it('deletes all sessions', () => {
      store.save({
        id: 'session-1',
        scope: 'exact' as const,
        pattern: 'tool1:/path1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      store.save({
        id: 'session-2',
        scope: 'tool' as const,
        pattern: 'tool2',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      const deleted = store.deleteAll();
      expect(deleted).toBe(2);
      expect(store.list().length).toBe(0);
    });
  });

  describe('prune', () => {
    it('removes expired sessions', () => {
      // Create an expired session
      store.save({
        id: 'expired',
        scope: 'exact' as const,
        pattern: 'old:/path',
        createdAt: new Date(Date.now() - 600000),
        expiresAt: new Date(Date.now() - 300000),
      });

      // Create a valid session
      store.save({
        id: 'valid',
        scope: 'exact' as const,
        pattern: 'new:/path',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      const pruned = store.prune();
      expect(pruned).toBe(1);

      // Verify expired session is gone
      expect(store.get('expired')).toBeNull();
      // Verify valid session still exists
      expect(store.get('valid')).not.toBeNull();
    });
  });

  describe('findByPattern', () => {
    beforeEach(() => {
      // Set up test sessions
      store.save({
        id: 'read-file-1',
        scope: 'tool' as const,
        pattern: 'read_file',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      store.save({
        id: 'read-file-2',
        scope: 'tool' as const,
        pattern: 'read_file',
        server: 'filesystem',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      store.save({
        id: 'write-file-1',
        scope: 'tool' as const,
        pattern: 'write_file',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000),
      });

      // Expired session
      store.save({
        id: 'expired-read',
        scope: 'tool' as const,
        pattern: 'read_file',
        createdAt: new Date(Date.now() - 600000),
        expiresAt: new Date(Date.now() - 300000),
      });
    });

    it('finds sessions by pattern', () => {
      const sessions = store.findByPattern('read_file');
      expect(sessions.length).toBe(2);
    });

    it('finds sessions by pattern and server', () => {
      const sessions = store.findByPattern('read_file', 'filesystem');
      expect(sessions.length).toBe(2); // Both the one with server and the one without (null server matches all)
    });

    it('does not return expired sessions', () => {
      const sessions = store.findByPattern('read_file');
      expect(sessions.every(s => s.id !== 'expired-read')).toBe(true);
    });

    it('returns empty array when no matches', () => {
      const sessions = store.findByPattern('non_existent_pattern');
      expect(sessions.length).toBe(0);
    });
  });

  describe('date handling', () => {
    it('correctly converts dates to and from storage', () => {
      const createdAt = new Date('2024-01-15T10:30:00.000Z');
      const expiresAt = new Date('2024-01-15T11:30:00.000Z');

      store.save({
        id: 'date-test',
        scope: 'exact' as const,
        pattern: 'test:/path',
        createdAt,
        expiresAt,
      });

      const retrieved = store.get('date-test');
      expect(retrieved?.createdAt.getTime()).toBe(createdAt.getTime());
      expect(retrieved?.expiresAt.getTime()).toBe(expiresAt.getTime());
    });
  });
});
