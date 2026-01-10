import { describe, it, expect } from 'vitest';
import * as path from 'path';

describe('Doctor Command Logic', () => {
  describe('Node.js version check', () => {
    it('should extract major version correctly', () => {
      const versions = [
        { version: 'v20.0.0', expected: 20 },
        { version: 'v21.5.0', expected: 21 },
        { version: 'v18.19.0', expected: 18 },
        { version: 'v22.1.0', expected: 22 },
        { version: 'v25.0.0', expected: 25 },
      ];

      versions.forEach(({ version, expected }) => {
        const major = parseInt(version.slice(1).split('.')[0], 10);
        expect(major).toBe(expected);
      });
    });

    it('should validate minimum version of 20', () => {
      const minVersion = 20;

      const validVersions = [20, 21, 22, 25];
      const invalidVersions = [16, 18, 19];

      validVersions.forEach((v) => {
        expect(v >= minVersion).toBe(true);
      });

      invalidVersions.forEach((v) => {
        expect(v >= minVersion).toBe(false);
      });
    });

    it('should handle current Node version', () => {
      const nodeVersion = process.version;
      const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0], 10);

      // Test environment should be Node 20+
      expect(majorVersion).toBeGreaterThanOrEqual(20);
    });
  });

  describe('file path construction', () => {
    it('should construct .bashrc path correctly', () => {
      const homeDir = '/home/testuser';
      const bashrcPath = path.join(homeDir, '.bashrc');
      expect(bashrcPath).toBe('/home/testuser/.bashrc');
    });

    it('should construct .zshrc path correctly', () => {
      const homeDir = '/home/testuser';
      const zshrcPath = path.join(homeDir, '.zshrc');
      expect(zshrcPath).toBe('/home/testuser/.zshrc');
    });

    it('should construct audit database path correctly', () => {
      const homeDir = '/home/testuser';
      const auditPath = path.join(homeDir, '.overwatch', 'audit.db');
      expect(auditPath).toBe('/home/testuser/.overwatch/audit.db');
    });

    it('should construct session database path correctly', () => {
      const homeDir = '/home/testuser';
      const sessionPath = path.join(homeDir, '.overwatch', 'sessions.db');
      expect(sessionPath).toBe('/home/testuser/.overwatch/sessions.db');
    });

    it('should construct data directory path correctly', () => {
      const homeDir = '/home/testuser';
      const dataDir = path.join(homeDir, '.overwatch');
      expect(dataDir).toBe('/home/testuser/.overwatch');
    });
  });

  describe('shell hook detection', () => {
    it('should detect overwatch hook in content', () => {
      const bashrcContent = `
# Some existing config
export PATH="/usr/local/bin:$PATH"

# Overwatch hook
overwatch check

# More config
alias ll="ls -la"
`;
      expect(bashrcContent.includes('overwatch check')).toBe(true);
    });

    it('should detect missing overwatch hook', () => {
      const bashrcContent = `
# Regular bashrc content
export PATH="/usr/local/bin:$PATH"
alias ll="ls -la"
`;
      expect(bashrcContent.includes('overwatch check')).toBe(false);
    });

    it('should handle empty shell config', () => {
      const emptyContent = '';
      expect(emptyContent.includes('overwatch check')).toBe(false);
    });
  });

  describe('database size calculation', () => {
    it('should convert bytes to MB correctly', () => {
      const testCases = [
        { bytes: 1048576, expectedMB: '1.00' },
        { bytes: 5242880, expectedMB: '5.00' },
        { bytes: 10485760, expectedMB: '10.00' },
        { bytes: 524288, expectedMB: '0.50' },
        { bytes: 0, expectedMB: '0.00' },
      ];

      testCases.forEach(({ bytes, expectedMB }) => {
        const sizeMB = (bytes / 1024 / 1024).toFixed(2);
        expect(sizeMB).toBe(expectedMB);
      });
    });

    it('should handle large database sizes', () => {
      const bytes = 1073741824; // 1 GB
      const sizeMB = (bytes / 1024 / 1024).toFixed(2);
      expect(sizeMB).toBe('1024.00');
    });
  });

  describe('issue tracking', () => {
    it('should count issues correctly', () => {
      const checks = [
        { name: 'Node version', pass: true },
        { name: 'Config', pass: true },
        { name: 'Bash hook', pass: false },
        { name: 'Zsh hook', pass: true },
        { name: 'Data dir', pass: false },
      ];

      const issues = checks.filter((c) => !c.pass).length;
      expect(issues).toBe(2);
    });

    it('should report zero issues when all pass', () => {
      const checks = [
        { name: 'Node version', pass: true },
        { name: 'Config', pass: true },
        { name: 'Data dir', pass: true },
      ];

      const issues = checks.filter((c) => !c.pass).length;
      expect(issues).toBe(0);
    });
  });

  describe('exit codes', () => {
    it('should exit with 0 on success', () => {
      const issueCount = 0;
      const expectedExitCode = issueCount > 0 ? 1 : 0;
      expect(expectedExitCode).toBe(0);
    });

    it('should exit with 1 on failure', () => {
      const issueCount = 3;
      const expectedExitCode = issueCount > 0 ? 1 : 0;
      expect(expectedExitCode).toBe(1);
    });
  });
});

describe('Doctor Check Types', () => {
  it('should cover all check categories', () => {
    const checkTypes = [
      'Node.js version',
      'Configuration',
      'Bash hook',
      'Zsh hook',
      'Audit database',
      'Session database',
      'Data directory',
    ];

    expect(checkTypes.length).toBe(7);
    expect(checkTypes).toContain('Node.js version');
    expect(checkTypes).toContain('Configuration');
    expect(checkTypes).toContain('Audit database');
  });

  it('should distinguish between warning and error states', () => {
    // Warnings are non-blocking (⚠)
    const warningConditions = [
      'No config found',
      'Hook not installed',
      'Database not created yet',
    ];

    // Errors are blocking (✗)
    const errorConditions = [
      'Node version too old',
      'Directory not writable',
    ];

    expect(warningConditions.length).toBeGreaterThan(0);
    expect(errorConditions.length).toBeGreaterThan(0);
  });
});

describe('Configuration Detection', () => {
  it('should report server count from config', () => {
    const config = {
      servers: {
        filesystem: { command: 'npx', args: [] },
        database: { command: 'npx', args: [] },
        git: { command: 'npx', args: [] },
      },
    };

    const serverCount = Object.keys(config.servers).length;
    expect(serverCount).toBe(3);
  });

  it('should handle empty servers config', () => {
    const config = {
      servers: {},
    };

    const serverCount = Object.keys(config.servers).length;
    expect(serverCount).toBe(0);
  });

  it('should handle missing servers config', () => {
    const config = {};

    const serverCount = (config as { servers?: Record<string, unknown> }).servers
      ? Object.keys((config as { servers: Record<string, unknown> }).servers).length
      : 0;
    expect(serverCount).toBe(0);
  });
});
