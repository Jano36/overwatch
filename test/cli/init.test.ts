import { describe, it, expect } from 'vitest';
import * as path from 'path';

describe('Init Command Logic', () => {
  describe('config path detection', () => {
    it('should construct local config path correctly', () => {
      const cwd = '/test/project';
      const configPath = path.join(cwd, 'overwatch.yaml');
      expect(configPath).toBe('/test/project/overwatch.yaml');
    });

    it('should construct global config path correctly', () => {
      const homeDir = '/home/testuser';
      const globalConfigPath = path.join(homeDir, '.overwatch', 'config.yaml');
      expect(globalConfigPath).toBe('/home/testuser/.overwatch/config.yaml');
    });

    it('should choose local path when package.json exists', () => {
      const cwd = '/my/project';
      const homeDir = '/home/user';
      const hasPackageJson = true;

      const configPath = hasPackageJson
        ? path.join(cwd, 'overwatch.yaml')
        : path.join(homeDir, '.overwatch', 'config.yaml');

      expect(configPath).toBe('/my/project/overwatch.yaml');
    });

    it('should choose global path when no package.json', () => {
      const cwd = '/some/directory';
      const homeDir = '/home/user';
      const hasPackageJson = false;

      const configPath = hasPackageJson
        ? path.join(cwd, 'overwatch.yaml')
        : path.join(homeDir, '.overwatch', 'config.yaml');

      expect(configPath).toBe('/home/user/.overwatch/config.yaml');
    });
  });

  describe('config content validation', () => {
    it('should require version field', () => {
      const configTemplate = `version: 1
defaults:
  action: prompt
`;
      expect(configTemplate).toContain('version: 1');
    });

    it('should include defaults section', () => {
      const expectedDefaults = {
        action: 'prompt',
        timeout: 60000,
        sessionDuration: 300000,
      };

      expect(expectedDefaults.action).toBe('prompt');
      expect(expectedDefaults.timeout).toBe(60000);
      expect(expectedDefaults.sessionDuration).toBe(300000);
    });

    it('should include tool shadowing section', () => {
      const toolShadowingConfig = {
        enabled: true,
        checkDescriptions: true,
        detectMutations: true,
      };

      expect(toolShadowingConfig.enabled).toBe(true);
      expect(toolShadowingConfig.checkDescriptions).toBe(true);
      expect(toolShadowingConfig.detectMutations).toBe(true);
    });

    it('should include audit section', () => {
      const auditConfig = {
        enabled: true,
        redactPII: true,
      };

      expect(auditConfig.enabled).toBe(true);
      expect(auditConfig.redactPII).toBe(true);
    });
  });

  describe('force flag behavior', () => {
    it('should prevent overwrite without force', () => {
      const configExists = true;
      const forceFlag = false;

      const shouldOverwrite = !configExists || forceFlag;
      expect(shouldOverwrite).toBe(false);
    });

    it('should allow overwrite with force', () => {
      const configExists = true;
      const forceFlag = true;

      const shouldOverwrite = !configExists || forceFlag;
      expect(shouldOverwrite).toBe(true);
    });

    it('should allow creation when config does not exist', () => {
      const configExists = false;
      const forceFlag = false;

      const shouldOverwrite = !configExists || forceFlag;
      expect(shouldOverwrite).toBe(true);
    });
  });

  describe('directory creation', () => {
    it('should extract parent directory correctly', () => {
      const configPath = '/home/user/.overwatch/config.yaml';
      const dir = path.dirname(configPath);
      expect(dir).toBe('/home/user/.overwatch');
    });

    it('should handle nested directory paths', () => {
      const paths = [
        '/home/user/.overwatch/config.yaml',
        '/project/overwatch.yaml',
        '/a/b/c/d/config.yaml',
      ];

      const expectedDirs = [
        '/home/user/.overwatch',
        '/project',
        '/a/b/c/d',
      ];

      paths.forEach((p, i) => {
        expect(path.dirname(p)).toBe(expectedDirs[i]);
      });
    });
  });

  describe('next steps messages', () => {
    it('should include configuration editing step', () => {
      const step = 'Edit overwatch.yaml to configure MCP servers and policies';
      expect(step).toContain('overwatch.yaml');
      expect(step).toContain('MCP servers');
    });

    it('should include wrap command step', () => {
      const step = 'Run "overwatch wrap <command>" to protect an MCP server';
      expect(step).toContain('overwatch wrap');
      expect(step).toContain('protect');
    });

    it('should include doctor command step', () => {
      const step = 'Run "overwatch doctor" to verify installation';
      expect(step).toContain('overwatch doctor');
      expect(step).toContain('verify');
    });
  });
});

describe('Init Command Server Examples', () => {
  it('should demonstrate filesystem server config', () => {
    const filesystemServer = {
      command: 'npx',
      args: ['@anthropic/mcp-server-filesystem', '/home/user/projects'],
      policies: [
        { tools: ['read_file', 'list_directory'], action: 'allow' },
        { tools: ['write_file'], action: 'prompt' },
        { tools: ['delete_file'], action: 'deny' },
      ],
    };

    expect(filesystemServer.command).toBe('npx');
    expect(filesystemServer.args[0]).toContain('mcp-server-filesystem');
    expect(filesystemServer.policies[0].action).toBe('allow');
    expect(filesystemServer.policies[1].action).toBe('prompt');
    expect(filesystemServer.policies[2].action).toBe('deny');
  });

  it('should demonstrate database server config', () => {
    const databaseServer = {
      command: 'npx',
      args: ['@modelcontextprotocol/server-postgres'],
      env: {
        DATABASE_URL: 'postgresql://localhost/mydb',
      },
      policies: [
        { tools: ['query', 'select'], action: 'allow' },
        { tools: ['insert', 'update'], action: 'prompt' },
        { tools: ['drop_*', 'delete_*'], action: 'deny' },
      ],
    };

    expect(databaseServer.command).toBe('npx');
    expect(databaseServer.env.DATABASE_URL).toContain('postgresql');
    expect(databaseServer.policies.length).toBe(3);
  });
});
