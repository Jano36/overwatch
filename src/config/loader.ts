import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { parse as parseYaml } from 'yaml';
import type { OverwatchConfig } from './types.js';

const CONFIG_NAMES = [
  'overwatch.yaml',
  'overwatch.yml',
  '.overwatch.yaml',
  '.overwatch.yml',
];

export async function loadConfig(configPath?: string): Promise<OverwatchConfig> {
  // If explicit path provided, use it
  if (configPath) {
    return loadConfigFile(configPath);
  }

  // Search for config in current directory
  for (const name of CONFIG_NAMES) {
    const fullPath = path.join(process.cwd(), name);
    if (fs.existsSync(fullPath)) {
      return loadConfigFile(fullPath);
    }
  }

  // Search in home directory
  const homeDir = os.homedir();
  for (const name of CONFIG_NAMES) {
    const fullPath = path.join(homeDir, '.overwatch', name);
    if (fs.existsSync(fullPath)) {
      return loadConfigFile(fullPath);
    }
  }

  // Also check ~/.overwatch/config.yaml
  const globalConfig = path.join(homeDir, '.overwatch', 'config.yaml');
  if (fs.existsSync(globalConfig)) {
    return loadConfigFile(globalConfig);
  }

  // Return default config if none found
  return getDefaultConfig();
}

async function loadConfigFile(filePath: string): Promise<OverwatchConfig> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const config = parseYaml(content) as OverwatchConfig;

  // Validate and merge with defaults
  return mergeWithDefaults(config);
}

function mergeWithDefaults(config: Partial<OverwatchConfig>): OverwatchConfig {
  const defaults = getDefaultConfig();

  return {
    version: config.version || defaults.version,
    defaults: {
      ...defaults.defaults,
      ...config.defaults,
    },
    servers: config.servers,
    audit: {
      ...defaults.audit,
      ...config.audit,
    },
    toolShadowing: {
      ...defaults.toolShadowing,
      ...config.toolShadowing,
    },
  };
}

function getDefaultConfig(): OverwatchConfig {
  return {
    version: 1,
    defaults: {
      action: 'prompt',
      timeout: 60000,
      sessionDuration: 300000,
    },
    toolShadowing: {
      enabled: true,
      checkDescriptions: true,
      detectMutations: true,
    },
    audit: {
      enabled: true,
      redactPII: true,
    },
  };
}

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
  config?: OverwatchConfig;
}

export function validateConfig(content: string): ValidationResult {
  try {
    const config = parseYaml(content) as OverwatchConfig;
    const errors: string[] = [];

    // Check version
    if (config.version !== 1) {
      errors.push(`Unsupported config version: ${config.version}. Expected: 1`);
    }

    // Check defaults
    if (config.defaults?.action) {
      const validActions = ['prompt', 'allow', 'deny'];
      if (!validActions.includes(config.defaults.action)) {
        errors.push(`Invalid default action: ${config.defaults.action}. Valid: ${validActions.join(', ')}`);
      }
    }

    // Check servers
    if (config.servers) {
      for (const [name, server] of Object.entries(config.servers)) {
        if (!server.command) {
          errors.push(`Server '${name}' missing required 'command' field`);
        }

        if (server.policies) {
          for (const policy of server.policies) {
            if (policy.action) {
              const validActions = ['allow', 'prompt', 'deny', 'smart'];
              if (!validActions.includes(policy.action)) {
                errors.push(`Server '${name}' has invalid policy action: ${policy.action}`);
              }
            }
          }
        }
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true, config: mergeWithDefaults(config) };

  } catch (error) {
    return {
      valid: false,
      errors: [`YAML parse error: ${error instanceof Error ? error.message : String(error)}`],
    };
  }
}
