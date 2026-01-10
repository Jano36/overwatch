import type { OverwatchConfig, PolicyConfig, ServerConfig } from './types.js';

/**
 * Policy templates for common MCP server configurations.
 * These provide secure-by-default policies that can be customized.
 */

export interface PolicyTemplate {
  name: string;
  description: string;
  servers: Record<string, ServerConfig>;
  policies: PolicyConfig[];
}

/**
 * Template for filesystem-based MCP servers
 * Restricts access to sensitive paths and requires approval for writes
 */
export const filesystemTemplate: PolicyTemplate = {
  name: 'filesystem',
  description: 'Secure policy for filesystem MCP servers',
  servers: {},
  policies: [
    {
      tools: ['read_file', 'list_directory', 'search_files'],
      action: 'smart',
      paths: {
        allow: ['./src/**', './docs/**', './test/**'],
        deny: [
          '**/node_modules/**',
          '**/.git/**',
          '**/.env',
          '**/.env.*',
          '**/secrets/**',
          '**/credentials/**',
          '**/*.pem',
          '**/*.key',
          '**/id_rsa*',
          '**/id_ed25519*',
          '~/.ssh/**',
          '~/.aws/**',
          '~/.config/**',
        ],
      },
    },
    {
      tools: ['write_file', 'create_directory'],
      action: 'prompt',
      paths: {
        allow: ['./src/**', './docs/**', './test/**'],
        deny: [
          '**/node_modules/**',
          '**/.git/**',
          '**/package.json',
          '**/package-lock.json',
          '**/*.lock',
        ],
      },
    },
    {
      tools: ['delete_file', 'delete_directory', 'move_file'],
      action: 'prompt',
    },
  ],
};

/**
 * Template for database MCP servers
 * Allows reads, prompts for writes, denies destructive operations
 */
export const databaseTemplate: PolicyTemplate = {
  name: 'database',
  description: 'Secure policy for database MCP servers',
  servers: {},
  policies: [
    {
      tools: ['query', 'select', 'describe_*', 'show_*', 'list_*'],
      action: 'allow',
    },
    {
      tools: ['execute', 'run_sql', 'raw_query', 'insert', 'update'],
      action: 'prompt',
    },
    {
      tools: ['*_schema', '*_table', '*_index', 'migrate*', 'drop_*', 'delete_*', 'truncate_*'],
      action: 'deny',
    },
  ],
};

/**
 * Template for HTTP/API MCP servers
 * Restricts potentially dangerous HTTP operations
 */
export const httpTemplate: PolicyTemplate = {
  name: 'http',
  description: 'Secure policy for HTTP/API MCP servers',
  servers: {},
  policies: [
    {
      tools: ['fetch', 'get', 'request', 'http_get', 'api_get'],
      action: 'allow',
    },
    {
      tools: ['post', 'put', 'patch', 'http_post', 'http_put', 'api_*'],
      action: 'prompt',
    },
    {
      tools: ['delete', 'http_delete'],
      action: 'prompt',
    },
  ],
};

/**
 * Template for shell/command execution MCP servers
 * Very restrictive - most operations require approval
 */
export const shellTemplate: PolicyTemplate = {
  name: 'shell',
  description: 'Restrictive policy for shell command execution',
  servers: {},
  policies: [
    {
      // Safe read-only commands
      tools: ['pwd', 'whoami', 'date', 'echo', 'cat', 'head', 'tail', 'ls', 'tree'],
      action: 'allow',
    },
    {
      // Common dev commands - prompt
      tools: [
        'npm',
        'yarn',
        'pnpm',
        'bun',
        'node',
        'go',
        'cargo',
        'python',
        'pip',
        'git',
        'make',
      ],
      action: 'prompt',
    },
    {
      // Dangerous commands - deny
      tools: [
        'rm',
        'sudo',
        'su',
        'chmod',
        'chown',
        'curl',
        'wget',
        'ssh',
        'nc',
        'netcat',
        'dd',
        'mkfs',
        'fdisk',
        'systemctl',
        'service',
      ],
      action: 'deny',
    },
    {
      // Default: prompt for unknown commands
      tools: ['*'],
      action: 'prompt',
    },
  ],
};

/**
 * Template for AI coding assistants (Claude, Cursor, Copilot)
 * Balanced between productivity and security
 */
export const codingAssistantTemplate: PolicyTemplate = {
  name: 'coding-assistant',
  description: 'Balanced policy for AI coding assistants',
  servers: {},
  policies: [
    {
      // Code reading is generally safe
      tools: ['read_*', 'list_*', 'search_*', 'find_*', 'grep*'],
      action: 'allow',
      paths: {
        deny: ['**/.env*', '**/secrets/**', '**/*.pem', '**/*.key'],
      },
    },
    {
      // Code writing needs review
      tools: ['write_*', 'edit_*', 'create_*', 'update_*'],
      action: 'prompt',
    },
    {
      // File deletion is sensitive
      tools: ['delete_*', 'remove_*'],
      action: 'prompt',
    },
    {
      // Shell commands need careful review
      tools: ['run_command', 'execute', 'shell', 'bash'],
      action: 'prompt',
    },
    {
      // Browser/web tools
      tools: ['browse*', 'fetch*', 'screenshot*'],
      action: 'prompt',
    },
  ],
};

/**
 * Strict template - deny by default, allowlist only
 * For high-security environments
 */
export const strictTemplate: PolicyTemplate = {
  name: 'strict',
  description: 'Deny-by-default policy for high-security environments',
  servers: {},
  policies: [
    {
      tools: ['*'],
      action: 'deny',
    },
  ],
};

/**
 * Audit-only template - allow all but log everything
 * For monitoring/learning phase
 */
export const auditOnlyTemplate: PolicyTemplate = {
  name: 'audit-only',
  description: 'Allow all operations but log everything for auditing',
  servers: {},
  policies: [
    {
      tools: ['*'],
      action: 'allow',
    },
  ],
};

/**
 * Registry of all available templates
 */
export const templates: Record<string, PolicyTemplate> = {
  filesystem: filesystemTemplate,
  database: databaseTemplate,
  http: httpTemplate,
  shell: shellTemplate,
  'coding-assistant': codingAssistantTemplate,
  strict: strictTemplate,
  'audit-only': auditOnlyTemplate,
};

/**
 * Get a template by name
 */
export function getTemplate(name: string): PolicyTemplate | undefined {
  return templates[name];
}

/**
 * List all available templates
 */
export function listTemplates(): Array<{ name: string; description: string }> {
  return Object.values(templates).map((t) => ({
    name: t.name,
    description: t.description,
  }));
}

/**
 * Apply a template to an existing config, merging policies
 */
export function applyTemplate(
  config: OverwatchConfig,
  templateName: string,
  serverName: string
): OverwatchConfig {
  const template = templates[templateName];
  if (!template) {
    throw new Error(`Unknown template: ${templateName}`);
  }

  const servers = config.servers || {};
  const existingServer = servers[serverName] || { command: '' };
  const existingPolicies = existingServer.policies || [];

  return {
    ...config,
    servers: {
      ...servers,
      [serverName]: {
        ...existingServer,
        policies: [...template.policies, ...existingPolicies],
      },
    },
  };
}

/**
 * Generate a starter config from a template
 */
export function generateConfig(
  templateName: string,
  serverName: string,
  command: string,
  args?: string[]
): OverwatchConfig {
  const template = templates[templateName];
  if (!template) {
    throw new Error(`Unknown template: ${templateName}`);
  }

  return {
    version: 1,
    defaults: {
      action: 'prompt',
      timeout: 30000,
      sessionDuration: 300000, // 5 minutes
    },
    servers: {
      [serverName]: {
        command,
        args,
        policies: template.policies,
      },
    },
    audit: {
      enabled: true,
      redactPII: true,
      retention: '30d',
    },
  };
}

/**
 * Common deny patterns that should be blocked across all templates
 */
export const commonDenyPatterns = {
  paths: [
    // Credentials
    '**/.env',
    '**/.env.*',
    '**/secrets/**',
    '**/credentials/**',
    '**/*.pem',
    '**/*.key',
    '**/*.p12',
    '**/*.pfx',
    '**/id_rsa*',
    '**/id_ed25519*',
    '**/id_ecdsa*',
    '**/id_dsa*',
    '~/.ssh/**',
    '~/.aws/**',
    '~/.azure/**',
    '~/.gcloud/**',
    '~/.kube/**',

    // System
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/var/log/**',
    '/root/**',

    // Package managers
    '**/node_modules/**',
    '**/.git/**',
    '**/vendor/**',
    '**/__pycache__/**',
  ],
  commands: [
    // Dangerous shell commands
    'rm -rf /',
    'rm -rf /*',
    ':(){ :|:& };:', // Fork bomb
    'mkfs',
    'dd if=/dev/zero',
    'chmod 777',
    'curl | sh',
    'wget | sh',
    'curl | bash',
    'wget | bash',
  ],
};

/**
 * Guardrail patterns for prompt injection detection
 */
export const guardrailPatterns = {
  promptInjection: [
    'ignore previous instructions',
    'ignore all previous',
    'disregard above',
    'forget your instructions',
    'new instructions:',
    'system prompt:',
    'you are now',
    'pretend you are',
    'act as if',
    'roleplay as',
    'jailbreak',
    'DAN mode',
  ],
  exfiltration: [
    'send to',
    'post to',
    'upload to',
    'exfiltrate',
    'transfer to external',
    'webhook.site',
    'requestbin',
    'ngrok.io',
  ],
};
