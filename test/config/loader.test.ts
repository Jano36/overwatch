import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadConfig, validateConfig } from '../../src/config/loader.js';

describe('Config Loader', () => {
  let tempDir: string;

  beforeEach(() => {
    // Create a temporary directory for test files
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'overwatch-config-test-'));
  });

  afterEach(() => {
    // Clean up temp directory
    fs.rmSync(tempDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  describe('loadConfig with explicit path', () => {
    it('loads config from explicit path', async () => {
      const configPath = path.join(tempDir, 'custom-config.yaml');
      const configContent = `
version: 1
defaults:
  action: allow
  timeout: 30000
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.version).toBe(1);
      expect(config.defaults?.action).toBe('allow');
      expect(config.defaults?.timeout).toBe(30000);
    });

    it('throws error for nonexistent explicit path', async () => {
      const nonexistentPath = path.join(tempDir, 'nonexistent.yaml');

      await expect(loadConfig(nonexistentPath)).rejects.toThrow('Failed to read config file');
    });

    it('throws error for invalid YAML in explicit path', async () => {
      const invalidPath = path.join(tempDir, 'invalid.yaml');
      fs.writeFileSync(invalidPath, 'invalid: yaml: [broken');

      await expect(loadConfig(invalidPath)).rejects.toThrow('Failed to parse YAML');
    });

    it('throws error for directory path instead of file', async () => {
      await expect(loadConfig(tempDir)).rejects.toThrow();
    });

    it('loads config with server definitions', async () => {
      const configPath = path.join(tempDir, 'servers.yaml');
      const configContent = `
version: 1
servers:
  filesystem:
    command: npx
    args:
      - -y
      - "@modelcontextprotocol/server-filesystem"
    policies:
      - tools: read_file
        action: allow
      - tools: write_file
        action: prompt
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.filesystem).toBeDefined();
      expect(config.servers?.filesystem.command).toBe('npx');
      expect(config.servers?.filesystem.args).toEqual(['-y', '@modelcontextprotocol/server-filesystem']);
      expect(config.servers?.filesystem.policies).toHaveLength(2);
    });

    it('loads config with audit settings', async () => {
      const configPath = path.join(tempDir, 'audit.yaml');
      const configContent = `
version: 1
audit:
  enabled: true
  redactPII: true
  retention: 30d
  path: /var/log/overwatch
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.audit?.enabled).toBe(true);
      expect(config.audit?.redactPII).toBe(true);
      expect(config.audit?.retention).toBe('30d');
      expect(config.audit?.path).toBe('/var/log/overwatch');
    });

    it('loads config with tool shadowing settings', async () => {
      const configPath = path.join(tempDir, 'toolshadowing.yaml');
      const configContent = `
version: 1
toolShadowing:
  enabled: false
  checkDescriptions: true
  detectMutations: false
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.toolShadowing?.enabled).toBe(false);
      expect(config.toolShadowing?.checkDescriptions).toBe(true);
      expect(config.toolShadowing?.detectMutations).toBe(false);
    });
  });

  describe('mergeWithDefaults', () => {
    it('fills in missing defaults section', async () => {
      const configPath = path.join(tempDir, 'partial.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(config.defaults?.action).toBe('prompt');
      expect(config.defaults?.timeout).toBe(60000);
      expect(config.defaults?.sessionDuration).toBe(300000);
    });

    it('fills in missing toolShadowing section', async () => {
      const configPath = path.join(tempDir, 'partial.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(config.toolShadowing?.enabled).toBe(true);
      expect(config.toolShadowing?.checkDescriptions).toBe(true);
      expect(config.toolShadowing?.detectMutations).toBe(true);
    });

    it('fills in missing audit section', async () => {
      const configPath = path.join(tempDir, 'partial.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(config.audit?.enabled).toBe(true);
      expect(config.audit?.redactPII).toBe(true);
    });

    it('preserves user-specified values over defaults', async () => {
      const configPath = path.join(tempDir, 'custom.yaml');
      const configContent = `
version: 1
defaults:
  action: deny
  timeout: 10000
toolShadowing:
  enabled: false
audit:
  redactPII: false
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.defaults?.action).toBe('deny');
      expect(config.defaults?.timeout).toBe(10000);
      expect(config.toolShadowing?.enabled).toBe(false);
      expect(config.audit?.redactPII).toBe(false);
    });

    it('partially merges defaults section', async () => {
      const configPath = path.join(tempDir, 'partial-defaults.yaml');
      const configContent = `
version: 1
defaults:
  action: allow
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.defaults?.action).toBe('allow');
      expect(config.defaults?.timeout).toBe(60000); // default
      expect(config.defaults?.sessionDuration).toBe(300000); // default
    });

    it('merges toolShadowing with partial values', async () => {
      const configPath = path.join(tempDir, 'partial-shadowing.yaml');
      const configContent = `
version: 1
toolShadowing:
  enabled: false
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.toolShadowing?.enabled).toBe(false);
      expect(config.toolShadowing?.checkDescriptions).toBe(true); // default
      expect(config.toolShadowing?.detectMutations).toBe(true); // default
    });

    it('merges audit with partial values', async () => {
      const configPath = path.join(tempDir, 'partial-audit.yaml');
      const configContent = `
version: 1
audit:
  path: /custom/path
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.audit?.path).toBe('/custom/path');
      expect(config.audit?.enabled).toBe(true); // default
      expect(config.audit?.redactPII).toBe(true); // default
    });
  });

  describe('validateConfig', () => {
    it('validates a correct minimal config', () => {
      const content = 'version: 1\n';

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.errors).toBeUndefined();
      expect(result.config).toBeDefined();
    });

    it('validates a complete config', () => {
      const content = `
version: 1
defaults:
  action: prompt
  timeout: 60000
  sessionDuration: 300000
servers:
  filesystem:
    command: npx
    args:
      - -y
      - "@modelcontextprotocol/server-filesystem"
    policies:
      - tools: read_file
        action: allow
      - tools:
          - write_file
          - delete_file
        action: deny
toolShadowing:
  enabled: true
  checkDescriptions: true
  detectMutations: true
audit:
  enabled: true
  redactPII: true
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.config?.servers?.filesystem).toBeDefined();
    });

    it('rejects unsupported version', () => {
      const content = 'version: 2\n';

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Unsupported config version: 2. Expected: 1');
    });

    it('rejects invalid default action', () => {
      const content = `
version: 1
defaults:
  action: invalid
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors?.some(e => e.includes('Invalid default action'))).toBe(true);
    });

    it('allows valid default actions', () => {
      const validActions = ['prompt', 'allow', 'deny'];

      for (const action of validActions) {
        const content = `
version: 1
defaults:
  action: ${action}
`;
        const result = validateConfig(content);
        expect(result.valid).toBe(true);
      }
    });

    it('rejects server without command', () => {
      const content = `
version: 1
servers:
  broken-server:
    args:
      - some-arg
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors?.some(e => e.includes("Server 'broken-server' missing required 'command' field"))).toBe(true);
    });

    it('rejects invalid policy action', () => {
      const content = `
version: 1
servers:
  test-server:
    command: test-cmd
    policies:
      - tools: some_tool
        action: invalid
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors?.some(e => e.includes('invalid policy action'))).toBe(true);
    });

    it('allows valid policy actions', () => {
      const validActions = ['allow', 'prompt', 'deny', 'smart'];

      for (const action of validActions) {
        const content = `
version: 1
servers:
  test-server:
    command: test-cmd
    policies:
      - tools: some_tool
        action: ${action}
`;
        const result = validateConfig(content);
        expect(result.valid).toBe(true);
      }
    });

    it('returns YAML parse error for invalid syntax', () => {
      const content = 'invalid: yaml: [broken';

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors?.some(e => e.includes('YAML parse error'))).toBe(true);
    });

    it('validates multiple servers', () => {
      const content = `
version: 1
servers:
  filesystem:
    command: npx
    args:
      - -y
      - server-filesystem
  database:
    command: npx
    args:
      - -y
      - server-postgres
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.config?.servers?.filesystem).toBeDefined();
      expect(result.config?.servers?.database).toBeDefined();
    });

    it('collects multiple validation errors', () => {
      const content = `
version: 2
defaults:
  action: invalid
servers:
  broken:
    args:
      - missing-command
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(false);
      expect(result.errors?.length).toBeGreaterThanOrEqual(2);
    });

    it('validates policy with path rules', () => {
      const content = `
version: 1
servers:
  filesystem:
    command: npx
    policies:
      - tools: write_file
        action: smart
        paths:
          allow:
            - /home/user/projects/**
          deny:
            - /etc/**
            - /usr/**
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.config?.servers?.filesystem.policies?.[0].paths?.allow).toContain('/home/user/projects/**');
    });

    it('validates policy with tool array', () => {
      const content = `
version: 1
servers:
  filesystem:
    command: npx
    policies:
      - tools:
          - read_file
          - write_file
          - list_directory
        action: prompt
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
    });

    it('handles empty config as invalid', () => {
      const content = '';

      const result = validateConfig(content);

      // Empty config parses as null/undefined, version check fails
      expect(result.valid).toBe(false);
    });

    it('handles null config values gracefully', () => {
      const content = `
version: 1
defaults: null
servers: null
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
    });

    it('validates server with environment variables', () => {
      const content = `
version: 1
servers:
  api-server:
    command: node
    args:
      - server.js
    env:
      NODE_ENV: production
      API_PORT: "3000"
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.config?.servers?.['api-server'].env?.NODE_ENV).toBe('production');
    });

    it('validates server with multiple policies', () => {
      const content = `
version: 1
servers:
  filesystem:
    command: npx
    policies:
      - tools: read_file
        action: allow
      - tools:
          - write_file
          - create_directory
        action: prompt
      - tools: delete_file
        action: deny
`;

      const result = validateConfig(content);

      expect(result.valid).toBe(true);
      expect(result.config?.servers?.filesystem.policies).toHaveLength(3);
    });

    it('validates config with analyzer field (deprecated)', () => {
      const content = `
version: 1
servers:
  filesystem:
    command: npx
    policies:
      - tools: write_file
        action: smart
        analyzer: semantic
`;

      const result = validateConfig(content);

      // Should still be valid even with deprecated field
      expect(result.valid).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('handles config with only version', async () => {
      const configPath = path.join(tempDir, 'minimal.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(config.version).toBe(1);
      // All defaults should be applied
      expect(config.defaults).toBeDefined();
      expect(config.toolShadowing).toBeDefined();
      expect(config.audit).toBeDefined();
    });

    it('handles config with whitespace and comments', async () => {
      const configPath = path.join(tempDir, 'commented.yaml');
      const configContent = `
# This is a comment
version: 1  # inline comment

# Defaults section
defaults:
  action: allow  # allow all by default

# Servers configuration
# (none defined yet)
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.version).toBe(1);
      expect(config.defaults?.action).toBe('allow');
    });

    it('handles unicode in config values', async () => {
      const configPath = path.join(tempDir, 'unicode.yaml');
      const configContent = `
version: 1
servers:
  test-server:
    command: echo
    args:
      - "Hello 世界"
      - "Привет"
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.['test-server'].args).toContain('Hello 世界');
    });

    it('handles deeply nested config', async () => {
      const configPath = path.join(tempDir, 'nested.yaml');
      const configContent = `
version: 1
servers:
  complex-server:
    command: node
    args:
      - server.js
    env:
      CONFIG: "nested"
    policies:
      - tools:
          - tool_a
          - tool_b
        action: smart
        paths:
          allow:
            - /path/one/**
            - /path/two/**
          deny:
            - /path/one/secret/**
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.['complex-server'].policies?.[0].paths?.deny).toContain('/path/one/secret/**');
    });

    it('handles empty strings in config', async () => {
      const configPath = path.join(tempDir, 'empty-strings.yaml');
      const configContent = `
version: 1
servers:
  test:
    command: test
    args:
      - ""
      - arg2
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.test.args).toContain('');
    });

    it('handles numeric version', async () => {
      const configPath = path.join(tempDir, 'numeric.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(typeof config.version).toBe('number');
      expect(config.version).toBe(1);
    });

    it('handles string version that parses as string', async () => {
      const configPath = path.join(tempDir, 'string-version.yaml');
      fs.writeFileSync(configPath, 'version: "1"\n');

      const config = await loadConfig(configPath);

      expect(config.version).toBe('1');
    });

    it('handles large config file', async () => {
      const configPath = path.join(tempDir, 'large.yaml');
      let configContent = 'version: 1\nservers:\n';

      // Create 50 server definitions
      for (let i = 0; i < 50; i++) {
        configContent += `  server-${i}:\n    command: cmd-${i}\n`;
      }
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(Object.keys(config.servers || {}).length).toBe(50);
    });

    it('handles config with special YAML characters', async () => {
      const configPath = path.join(tempDir, 'special-chars.yaml');
      const configContent = `
version: 1
servers:
  test:
    command: "cmd with: colon"
    args:
      - "arg with [brackets]"
      - "arg with {braces}"
      - "arg with 'single quotes'"
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.test.command).toBe('cmd with: colon');
      expect(config.servers?.test.args).toContain('arg with [brackets]');
    });

    it('handles multiline string values', async () => {
      const configPath = path.join(tempDir, 'multiline.yaml');
      const configContent = `
version: 1
servers:
  test:
    command: echo
    args:
      - |
        This is a
        multiline string
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.test.args?.[0]).toContain('multiline string');
    });

    it('handles boolean values correctly', async () => {
      const configPath = path.join(tempDir, 'booleans.yaml');
      const configContent = `
version: 1
toolShadowing:
  enabled: true
  checkDescriptions: false
  detectMutations: true
audit:
  enabled: false
  redactPII: true
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.toolShadowing?.enabled).toBe(true);
      expect(config.toolShadowing?.checkDescriptions).toBe(false);
      expect(config.audit?.enabled).toBe(false);
      expect(config.audit?.redactPII).toBe(true);
    });

    it('handles numeric string values', async () => {
      const configPath = path.join(tempDir, 'numeric-strings.yaml');
      const configContent = `
version: 1
servers:
  test:
    command: server
    env:
      PORT: "3000"
      MAX_CONNECTIONS: "100"
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);

      expect(config.servers?.test.env?.PORT).toBe('3000');
      expect(config.servers?.test.env?.MAX_CONNECTIONS).toBe('100');
    });
  });

  describe('config structure after loading', () => {
    it('has correct structure for minimal config', async () => {
      const configPath = path.join(tempDir, 'minimal.yaml');
      fs.writeFileSync(configPath, 'version: 1\n');

      const config = await loadConfig(configPath);

      expect(config).toHaveProperty('version');
      expect(config).toHaveProperty('defaults');
      expect(config).toHaveProperty('toolShadowing');
      expect(config).toHaveProperty('audit');
    });

    it('preserves server structure', async () => {
      const configPath = path.join(tempDir, 'server-structure.yaml');
      const configContent = `
version: 1
servers:
  myserver:
    command: node
    args:
      - server.js
    env:
      NODE_ENV: test
    policies:
      - tools: read_file
        action: allow
`;
      fs.writeFileSync(configPath, configContent);

      const config = await loadConfig(configPath);
      const server = config.servers?.myserver;

      expect(server).toHaveProperty('command');
      expect(server).toHaveProperty('args');
      expect(server).toHaveProperty('env');
      expect(server).toHaveProperty('policies');
      expect(server?.policies?.[0]).toHaveProperty('tools');
      expect(server?.policies?.[0]).toHaveProperty('action');
    });
  });

  describe('validation result structure', () => {
    it('returns correct structure for valid config', () => {
      const content = 'version: 1\n';

      const result = validateConfig(content);

      expect(result).toHaveProperty('valid', true);
      expect(result).toHaveProperty('config');
      expect(result).not.toHaveProperty('errors');
    });

    it('returns correct structure for invalid config', () => {
      const content = 'version: 99\n';

      const result = validateConfig(content);

      expect(result).toHaveProperty('valid', false);
      expect(result).toHaveProperty('errors');
      expect(Array.isArray(result.errors)).toBe(true);
    });
  });
});
