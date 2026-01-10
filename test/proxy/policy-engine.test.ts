import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PolicyEngine } from '../../src/proxy/policy-engine.js';
import type { OverwatchConfig } from '../../src/config/types.js';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

describe('PolicyEngine', () => {
  const validConfig: OverwatchConfig = {
    version: 1,
    defaults: {
      action: 'prompt',
    },
    servers: {
      filesystem: {
        command: 'npx',
        args: ['-y', '@anthropic-ai/mcp-server-filesystem'],
        policies: [
          {
            tools: ['read_file', 'list_*'],
            action: 'allow',
          },
          {
            tools: ['write_file'],
            paths: {
              allow: ['/tmp/*', '/home/user/projects/*'],
              deny: ['/etc/*', '/root/*'],
            },
          },
          {
            tools: ['delete_*'],
            action: 'deny',
          },
        ],
      },
    },
  };

  describe('constructor', () => {
    it('creates engine with valid config', () => {
      const engine = new PolicyEngine(validConfig);
      expect(engine).toBeDefined();
      engine.close();
    });

    it('throws on invalid config version', () => {
      const invalidConfig = { ...validConfig, version: 2 };
      expect(() => new PolicyEngine(invalidConfig)).toThrow('Policy validation failed');
    });

    it('throws on invalid default action', () => {
      const invalidConfig = {
        ...validConfig,
        defaults: { action: 'invalid' as 'prompt' },
      };
      expect(() => new PolicyEngine(invalidConfig)).toThrow('Policy validation failed');
    });

    it('throws on missing server command', () => {
      const invalidConfig: OverwatchConfig = {
        version: 1,
        servers: {
          broken: {
            command: '', // Empty command
          },
        },
      };
      expect(() => new PolicyEngine(invalidConfig)).toThrow('Policy validation failed');
    });
  });

  describe('validatePolicies (O-H17)', () => {
    it('validates tool patterns', () => {
      const configWithBadPattern: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['valid', 'tool|injection;bad'],
                action: 'allow',
              },
            ],
          },
        },
      };

      expect(() => new PolicyEngine(configWithBadPattern)).toThrow('Tool pattern contains invalid characters');
    });

    it('validates path patterns', () => {
      const configWithNullByte: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['*'],
                paths: {
                  deny: ['/etc/\0passwd'],
                },
              },
            ],
          },
        },
      };

      expect(() => new PolicyEngine(configWithNullByte)).toThrow('null byte');
    });

    it('warns on deprecated analyzer field', () => {
      const configWithAnalyzer: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['*'],
                analyzer: 'sql', // Deprecated
                action: 'prompt',
              },
            ],
          },
        },
      };

      const engine = new PolicyEngine(configWithAnalyzer);
      const validation = engine.validatePolicies();

      expect(validation.valid).toBe(true);
      expect(validation.warnings.some(w => w.code === 'DEPRECATED_ANALYZER')).toBe(true);
      engine.close();
    });

    it('warns on conflicting paths', () => {
      const configWithConflict: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['*'],
                paths: {
                  allow: ['/home/user/*'],
                  deny: ['/home/user/*'], // Same pattern in both
                },
              },
            ],
          },
        },
      };

      const engine = new PolicyEngine(configWithConflict);
      const validation = engine.validatePolicies();

      expect(validation.warnings.some(w => w.code === 'CONFLICTING_PATHS')).toBe(true);
      engine.close();
    });

    it('warns on empty policy', () => {
      const configWithEmptyPolicy: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [{}], // Empty policy
          },
        },
      };

      const engine = new PolicyEngine(configWithEmptyPolicy);
      const validation = engine.validatePolicies();

      expect(validation.warnings.some(w => w.code === 'EMPTY_POLICY')).toBe(true);
      engine.close();
    });

    it('fails in strict mode with warnings', () => {
      const configWithWarnings: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [{}], // Empty policy triggers warning
          },
        },
      };

      expect(
        () => new PolicyEngine(configWithWarnings, { strictValidation: true })
      ).toThrow('strict mode');
    });
  });

  describe('evaluate', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
      engine = new PolicyEngine(validConfig);
    });

    afterEach(() => {
      engine.close();
    });

    it('matches exact tool pattern', () => {
      const decision = engine.evaluate('filesystem', 'read_file', {});
      expect(decision.action).toBe('allow');
    });

    it('matches glob tool pattern', () => {
      const decision = engine.evaluate('filesystem', 'list_directory', {});
      expect(decision.action).toBe('allow');
    });

    it('denies path in deny list', () => {
      const decision = engine.evaluate('filesystem', 'write_file', { path: '/etc/passwd' });
      expect(decision.action).toBe('deny');
      expect(decision.riskLevel).toBe('dangerous');
    });

    it('allows path in allow list', () => {
      const decision = engine.evaluate('filesystem', 'write_file', { path: '/tmp/test.txt' });
      expect(decision.action).toBe('allow');
      expect(decision.riskLevel).toBe('safe');
    });

    it('matches delete pattern for deny', () => {
      const decision = engine.evaluate('filesystem', 'delete_file', {});
      expect(decision.action).toBe('deny');
    });

    it('uses default action for unknown server', () => {
      const decision = engine.evaluate('unknown-server', 'some_tool', {});
      expect(decision.action).toBe('prompt');
      expect(decision.reason).toBe('No server configuration found');
    });

    it('infers destructive from tool name', () => {
      const configWithNoPolicy: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [],
          },
        },
      };
      const eng = new PolicyEngine(configWithNoPolicy);

      const decision = eng.evaluate('test', 'drop_database', {});
      expect(decision.riskLevel).toBe('destructive');
      expect(decision.action).toBe('prompt');
      eng.close();
    });

    it('infers read from tool name', () => {
      const configWithNoPolicy: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [],
          },
        },
      };
      const eng = new PolicyEngine(configWithNoPolicy);

      const decision = eng.evaluate('test', 'get_user', {});
      expect(decision.riskLevel).toBe('read');
      expect(decision.action).toBe('allow');
      eng.close();
    });

    it('rejects ReDoS patterns (consecutive wildcards)', () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['dangerous**pattern'],
                action: 'deny',
              },
            ],
          },
        },
      };

      expect(() => new PolicyEngine(config)).toThrow('Consecutive wildcards are not allowed');
    });

    it('rejects ReDoS patterns (excessive wildcards)', () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                // 4 wildcards > 3 allowed
                tools: ['too*many*wild*cards*'],
                action: 'deny',
              },
            ],
          },
        },
      };

      expect(() => new PolicyEngine(config)).toThrow('Too many wildcards');
    });
  });

  describe('hot-reload (O-H18)', () => {
    let configPath: string;
    let engine: PolicyEngine;

    beforeEach(() => {
      configPath = path.join(os.tmpdir(), `test-config-${Date.now()}.yaml`);
      const initialConfig = `
version: 1
defaults:
  action: prompt
servers:
  test:
    command: test-cmd
    policies:
      - tools: ['read_*']
        action: allow
`;
      fs.writeFileSync(configPath, initialConfig);
    });

    afterEach(() => {
      if (engine) {
        engine.close();
      }
      if (fs.existsSync(configPath)) {
        fs.unlinkSync(configPath);
      }
    });

    it('enables hot-reload when configured', async () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
          },
        },
      };

      engine = new PolicyEngine(config, {
        enableHotReload: true,
        configFilePath: configPath,
        reloadDebounceMs: 50,
      });

      // Wait for watcher to initialize
      await new Promise(r => setTimeout(r, 100));

      // Engine should have the file watcher set up
      expect(engine.getConfig()).toBeDefined();
    });

    it('emits reload event on config change', async () => {
      const config: OverwatchConfig = {
        version: 1,
        defaults: { action: 'prompt' },
        servers: {
          test: { command: 'test' },
        },
      };

      engine = new PolicyEngine(config, {
        enableHotReload: true,
        configFilePath: configPath,
        reloadDebounceMs: 50,
      });

      const reloadPromise = new Promise<void>((resolve) => {
        engine.once('reload', () => resolve());
      });

      // Modify the config file
      await new Promise(r => setTimeout(r, 100));
      const newConfig = `
version: 1
defaults:
  action: allow
servers:
  test:
    command: new-test-cmd
`;
      fs.writeFileSync(configPath, newConfig);

      await Promise.race([
        reloadPromise,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Reload timeout')), 2000)),
      ]);

      // Verify config was updated
      const currentConfig = engine.getConfig();
      expect(currentConfig.defaults?.action).toBe('allow');
    });

    it('emits error on invalid config reload', async () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: { command: 'test' },
        },
      };

      engine = new PolicyEngine(config, {
        enableHotReload: true,
        configFilePath: configPath,
        reloadDebounceMs: 50,
      });

      const errorPromise = new Promise<{ message: string }>((resolve) => {
        engine.once('reload-error', (err) => resolve(err));
      });

      // Write invalid config
      await new Promise(r => setTimeout(r, 100));
      const invalidConfig = `
version: 999
servers:
  test:
    command: ""
`;
      fs.writeFileSync(configPath, invalidConfig);

      const error = await Promise.race([
        errorPromise,
        new Promise<{ message: string }>((_, reject) =>
          setTimeout(() => reject(new Error('Error event timeout')), 2000)
        ),
      ]);

      expect(error.message).toContain('Validation failed');

      // Original config should be preserved
      expect(engine.getConfig().version).toBe(1);
    });

    it('stops watching when close() is called', async () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: { command: 'test' },
        },
      };

      engine = new PolicyEngine(config, {
        enableHotReload: true,
        configFilePath: configPath,
        reloadDebounceMs: 50,
      });

      // Close the engine
      engine.close();

      // Should not emit any events after close
      let reloadCalled = false;
      engine.on('reload', () => {
        reloadCalled = true;
      });

      // Modify config
      await new Promise(r => setTimeout(r, 100));
      fs.writeFileSync(configPath, 'version: 1\nservers:\n  test:\n    command: new');
      await new Promise(r => setTimeout(r, 200));

      expect(reloadCalled).toBe(false);
    });

    it('supports manual reload', async () => {
      const config: OverwatchConfig = {
        version: 1,
        defaults: { action: 'deny' },
        servers: {
          test: { command: 'test' },
        },
      };

      engine = new PolicyEngine(config, {
        enableHotReload: false, // Disabled
        configFilePath: configPath,
      });

      // Write new config
      const newConfig = `
version: 1
defaults:
  action: allow
servers:
  test:
    command: new-test-cmd
`;
      fs.writeFileSync(configPath, newConfig);

      // Manually reload
      const result = await engine.reload();
      expect(result.valid).toBe(true);
      expect(engine.getConfig().defaults?.action).toBe('allow');
    });
  });

  describe('compiled patterns', () => {
    it('uses pre-compiled patterns for performance', () => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['read_*', 'write_*', 'delete_*'],
                action: 'prompt',
              },
            ],
          },
        },
      };

      const engine = new PolicyEngine(config);

      // Multiple evaluations should use compiled patterns
      for (let i = 0; i < 100; i++) {
        engine.evaluate('test', `read_file_${i}`, {});
        engine.evaluate('test', `write_file_${i}`, {});
      }

      engine.close();
    });
  });

  describe('path extraction', () => {
    let engine: PolicyEngine;

    beforeEach(() => {
      const config: OverwatchConfig = {
        version: 1,
        servers: {
          test: {
            command: 'test',
            policies: [
              {
                tools: ['*'],
                paths: {
                  deny: ['/etc/*'],
                  allow: ['/tmp/*'],
                },
              },
            ],
          },
        },
      };
      engine = new PolicyEngine(config);
    });

    afterEach(() => {
      engine.close();
    });

    it('extracts path from various arg keys', () => {
      const pathKeys = ['path', 'file', 'filename', 'filepath', 'directory', 'dir'];

      for (const key of pathKeys) {
        const decision = engine.evaluate('test', 'tool', { [key]: '/etc/passwd' });
        expect(decision.action).toBe('deny');
      }
    });
  });
});
