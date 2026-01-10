import * as fs from 'fs';
import { EventEmitter } from 'events';
import type { PolicyConfig, RiskLevel, OverwatchConfig } from '../config/types.js';

export type PolicyAction = 'allow' | 'prompt' | 'deny';

export interface PolicyDecision {
  action: PolicyAction;
  riskLevel: RiskLevel;
  reason: string;
  matchedPolicy?: string;
}

/**
 * Result of validating a policy configuration.
 */
export interface PolicyValidationResult {
  valid: boolean;
  errors: PolicyValidationError[];
  warnings: PolicyValidationWarning[];
}

export interface PolicyValidationError {
  path: string;
  message: string;
  code: string;
}

export interface PolicyValidationWarning {
  path: string;
  message: string;
  code: string;
}

/**
 * Configuration for the policy engine.
 */
export interface PolicyEngineConfig {
  /** Enable hot-reload of config file */
  enableHotReload?: boolean;
  /** Config file path to watch for hot-reload */
  configFilePath?: string;
  /** Debounce interval for config file changes (ms) */
  reloadDebounceMs?: number;
  /** Validate policies strictly (fail on warnings) */
  strictValidation?: boolean;
}

/**
 * PolicyEngine evaluates MCP tool calls against configured policies.
 *
 * Simplified architecture (O-H15, O-H16):
 * - Declarative policy matching (tool patterns, path patterns)
 * - Risk inference from tool names
 * - No analyzer routing (analyzers removed in favor of focused features)
 *
 * Enhanced with (O-H17, O-H18):
 * - Policy validation on load
 * - Hot-reload capability
 */
export class PolicyEngine extends EventEmitter {
  private defaultAction: PolicyAction;
  private config: OverwatchConfig;
  private fileWatcher: fs.FSWatcher | null = null;
  private reloadTimer: ReturnType<typeof setTimeout> | null = null;
  private engineConfig: Required<PolicyEngineConfig>;
  private compiledPatterns: Map<string, RegExp> = new Map();

  constructor(config: OverwatchConfig, engineConfig?: PolicyEngineConfig) {
    super();
    this.config = config;
    this.defaultAction = (config.defaults?.action as PolicyAction) || 'prompt';

    this.engineConfig = {
      enableHotReload: engineConfig?.enableHotReload ?? false,
      configFilePath: engineConfig?.configFilePath ?? '',
      reloadDebounceMs: engineConfig?.reloadDebounceMs ?? 500,
      strictValidation: engineConfig?.strictValidation ?? false,
    };

    // Validate on load (O-H17)
    const validation = this.validatePolicies();
    if (!validation.valid) {
      const errorMessages = validation.errors.map(e => `${e.path}: ${e.message}`).join('; ');
      throw new Error(`Policy validation failed: ${errorMessages}`);
    }

    if (validation.warnings.length > 0 && this.engineConfig.strictValidation) {
      const warningMessages = validation.warnings.map(w => `${w.path}: ${w.message}`).join('; ');
      throw new Error(`Policy validation warnings (strict mode): ${warningMessages}`);
    }

    // Pre-compile patterns for performance
    this.compilePatterns();

    // Start hot-reload if enabled (O-H18)
    if (this.engineConfig.enableHotReload && this.engineConfig.configFilePath) {
      this.startWatching();
    }
  }

  /**
   * Validate all policies in the configuration (O-H17).
   */
  validatePolicies(): PolicyValidationResult {
    const errors: PolicyValidationError[] = [];
    const warnings: PolicyValidationWarning[] = [];

    // Validate version
    if (this.config.version !== 1) {
      errors.push({
        path: 'version',
        message: `Unsupported config version: ${this.config.version}. Expected: 1`,
        code: 'INVALID_VERSION',
      });
    }

    // Validate default action
    if (this.config.defaults?.action) {
      const validActions = ['prompt', 'allow', 'deny'];
      if (!validActions.includes(this.config.defaults.action)) {
        errors.push({
          path: 'defaults.action',
          message: `Invalid action: ${this.config.defaults.action}. Valid: ${validActions.join(', ')}`,
          code: 'INVALID_DEFAULT_ACTION',
        });
      }
    }

    // Validate servers and their policies
    if (this.config.servers) {
      for (const [serverName, serverConfig] of Object.entries(this.config.servers)) {
        // Check required command field
        if (!serverConfig.command) {
          errors.push({
            path: `servers.${serverName}.command`,
            message: 'Missing required command field',
            code: 'MISSING_COMMAND',
          });
        }

        // Validate policies
        if (serverConfig.policies) {
          for (let i = 0; i < serverConfig.policies.length; i++) {
            const policy = serverConfig.policies[i];
            const policyPath = `servers.${serverName}.policies[${i}]`;

            // Validate action
            if (policy.action) {
              const validActions = ['allow', 'prompt', 'deny', 'smart'];
              if (!validActions.includes(policy.action)) {
                errors.push({
                  path: `${policyPath}.action`,
                  message: `Invalid action: ${policy.action}`,
                  code: 'INVALID_POLICY_ACTION',
                });
              }
            }

            // Validate tool patterns
            if (policy.tools) {
              const tools = Array.isArray(policy.tools) ? policy.tools : [policy.tools];
              for (const toolPattern of tools) {
                const patternValidation = this.validateToolPattern(toolPattern);
                if (!patternValidation.valid) {
                  errors.push({
                    path: `${policyPath}.tools`,
                    message: patternValidation.error!,
                    code: 'INVALID_TOOL_PATTERN',
                  });
                }
              }
            }

            // Validate path patterns
            if (policy.paths) {
              for (const pathType of ['allow', 'deny'] as const) {
                const paths = policy.paths[pathType];
                if (paths) {
                  for (const pathPattern of paths) {
                    const patternValidation = this.validatePathPattern(pathPattern);
                    if (!patternValidation.valid) {
                      errors.push({
                        path: `${policyPath}.paths.${pathType}`,
                        message: patternValidation.error!,
                        code: 'INVALID_PATH_PATTERN',
                      });
                    }
                  }
                }
              }
            }

            // Warning: deprecated analyzer field
            if (policy.analyzer) {
              warnings.push({
                path: `${policyPath}.analyzer`,
                message: 'The analyzer field is deprecated and will be ignored',
                code: 'DEPRECATED_ANALYZER',
              });
            }

            // Warning: policy with no effect
            if (!policy.action && !policy.paths && !policy.tools) {
              warnings.push({
                path: policyPath,
                message: 'Policy has no action, paths, or tools defined - will have no effect',
                code: 'EMPTY_POLICY',
              });
            }

            // Warning: conflicting allow/deny paths
            if (policy.paths?.allow && policy.paths?.deny) {
              const conflicts = this.findConflictingPaths(policy.paths.allow, policy.paths.deny);
              for (const conflict of conflicts) {
                warnings.push({
                  path: `${policyPath}.paths`,
                  message: `Conflicting patterns: '${conflict.allow}' and '${conflict.deny}' may match same paths`,
                  code: 'CONFLICTING_PATHS',
                });
              }
            }
          }
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Validate a tool pattern.
   */
  private validateToolPattern(pattern: string): { valid: boolean; error?: string } {
    if (!pattern || pattern.length === 0) {
      return { valid: false, error: 'Empty tool pattern' };
    }

    if (pattern.length > 256) {
      return { valid: false, error: 'Tool pattern exceeds 256 characters' };
    }

    // Check for invalid characters
    if (/[<>"|;`$]/.test(pattern)) {
      return { valid: false, error: 'Tool pattern contains invalid characters' };
    }

    // Validate glob syntax
    try {
      const regex = this.patternToRegex(pattern);
      new RegExp(regex);
    } catch {
      return { valid: false, error: 'Invalid pattern syntax' };
    }

    return { valid: true };
  }

  /**
   * Validate a path pattern.
   */
  private validatePathPattern(pattern: string): { valid: boolean; error?: string } {
    if (!pattern || pattern.length === 0) {
      return { valid: false, error: 'Empty path pattern' };
    }

    if (pattern.length > 1024) {
      return { valid: false, error: 'Path pattern exceeds 1024 characters' };
    }

    // Check for null bytes
    if (pattern.includes('\0')) {
      return { valid: false, error: 'Path pattern contains null byte' };
    }

    return { valid: true };
  }

  /**
   * Find patterns that might conflict.
   */
  private findConflictingPaths(
    allowPaths: string[],
    denyPaths: string[]
  ): Array<{ allow: string; deny: string }> {
    const conflicts: Array<{ allow: string; deny: string }> = [];

    for (const allow of allowPaths) {
      for (const deny of denyPaths) {
        // Check for exact match or containment
        if (allow === deny) {
          conflicts.push({ allow, deny });
        } else if (allow.includes('*') && deny.includes('*')) {
          // Both are wildcards - might conflict
          if (allow.replace(/\*/g, '') === deny.replace(/\*/g, '')) {
            conflicts.push({ allow, deny });
          }
        }
      }
    }

    return conflicts;
  }

  /**
   * Pre-compile patterns for better performance.
   */
  private compilePatterns(): void {
    this.compiledPatterns.clear();

    if (!this.config.servers) return;

    for (const serverConfig of Object.values(this.config.servers)) {
      if (!serverConfig.policies) continue;

      for (const policy of serverConfig.policies) {
        if (policy.tools) {
          const tools = Array.isArray(policy.tools) ? policy.tools : [policy.tools];
          for (const pattern of tools) {
            if (pattern.includes('*') && !this.compiledPatterns.has(pattern)) {
              try {
                this.compiledPatterns.set(pattern, new RegExp(this.patternToRegex(pattern)));
              } catch {
                // Pattern already validated, should not fail
              }
            }
          }
        }
      }
    }
  }

  /**
   * Convert glob pattern to regex string.
   */
  private patternToRegex(pattern: string): string {
    return '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
  }

  /**
   * Start watching config file for changes (O-H18).
   */
  private startWatching(): void {
    if (this.fileWatcher) {
      return;
    }

    const configPath = this.engineConfig.configFilePath;
    if (!configPath || !fs.existsSync(configPath)) {
      return;
    }

    this.fileWatcher = fs.watch(configPath, (eventType) => {
      if (eventType === 'change') {
        this.scheduleReload();
      }
    });

    this.fileWatcher.on('error', (error) => {
      this.emit('watch-error', error);
    });
  }

  /**
   * Schedule a debounced reload.
   */
  private scheduleReload(): void {
    if (this.reloadTimer) {
      clearTimeout(this.reloadTimer);
    }

    this.reloadTimer = setTimeout(() => {
      this.reloadConfig();
    }, this.engineConfig.reloadDebounceMs);
  }

  /**
   * Reload configuration from file.
   */
  private async reloadConfig(): Promise<void> {
    const configPath = this.engineConfig.configFilePath;
    if (!configPath || !fs.existsSync(configPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      const { parse: parseYaml } = await import('yaml');
      const newConfig = parseYaml(content) as OverwatchConfig;

      // Validate new config
      const oldConfig = this.config;
      this.config = newConfig;
      const validation = this.validatePolicies();

      if (!validation.valid) {
        // Revert to old config
        this.config = oldConfig;
        this.emit('reload-error', {
          errors: validation.errors,
          message: 'Validation failed, keeping previous config',
        });
        return;
      }

      // Apply new config
      this.defaultAction = (newConfig.defaults?.action as PolicyAction) || 'prompt';
      this.compilePatterns();

      this.emit('reload', {
        warnings: validation.warnings,
        timestamp: new Date(),
      });
    } catch (error) {
      this.emit('reload-error', {
        error,
        message: 'Failed to reload config',
      });
    }
  }

  /**
   * Stop watching config file.
   */
  stopWatching(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = null;
    }
    if (this.reloadTimer) {
      clearTimeout(this.reloadTimer);
      this.reloadTimer = null;
    }
  }

  /**
   * Manually trigger a config reload.
   */
  async reload(): Promise<PolicyValidationResult> {
    await this.reloadConfig();
    return this.validatePolicies();
  }

  /**
   * Get current config (for debugging/inspection).
   */
  getConfig(): OverwatchConfig {
    return { ...this.config };
  }

  evaluate(
    serverName: string,
    tool: string,
    args: Record<string, unknown>
  ): PolicyDecision {
    const serverConfig = this.config.servers?.[serverName];
    if (!serverConfig) {
      return {
        action: this.defaultAction,
        riskLevel: 'write',
        reason: 'No server configuration found',
      };
    }

    const policies = serverConfig.policies || [];

    // Find matching policy
    for (const policy of policies) {
      if (this.matchesPolicy(policy, tool)) {
        const decision = this.evaluatePolicy(policy, tool, args);
        if (decision) {
          return {
            ...decision,
            matchedPolicy: this.policyDescription(policy),
          };
        }
      }
    }

    // No specific policy, infer from tool name
    return this.inferFromToolName(tool);
  }

  private matchesPolicy(policy: PolicyConfig, tool: string): boolean {
    if (!policy.tools) return true; // Global policy

    const tools = Array.isArray(policy.tools) ? policy.tools : [policy.tools];

    for (const pattern of tools) {
      if (pattern === '*') return true;
      if (pattern === tool) return true;
      if (pattern.includes('*')) {
        // Use pre-compiled pattern if available
        const compiledPattern = this.compiledPatterns.get(pattern);
        if (compiledPattern) {
          if (compiledPattern.test(tool)) return true;
        } else {
          const regex = new RegExp(this.patternToRegex(pattern));
          if (regex.test(tool)) return true;
        }
      }
    }

    return false;
  }

  private evaluatePolicy(
    policy: PolicyConfig,
    _tool: string,
    args: Record<string, unknown>
  ): PolicyDecision | null {
    // Check path-based rules
    if (policy.paths) {
      const pathArg = this.extractPath(args);
      if (pathArg) {
        if (policy.paths.deny?.some((p) => this.matchPath(pathArg, p))) {
          return {
            action: 'deny',
            riskLevel: 'dangerous',
            reason: `Path matches deny pattern`,
          };
        }
        if (policy.paths.allow?.some((p) => this.matchPath(pathArg, p))) {
          return {
            action: 'allow',
            riskLevel: 'safe',
            reason: `Path matches allow pattern`,
          };
        }
      }
    }

    // Use static action
    if (policy.action && policy.action !== 'smart') {
      return {
        action: policy.action,
        riskLevel: 'write',
        reason: 'Policy static action',
      };
    }

    return null;
  }

  private inferFromToolName(tool: string): PolicyDecision {
    const toolLower = tool.toLowerCase();

    // Destructive operations
    if (
      toolLower.includes('delete') ||
      toolLower.includes('remove') ||
      toolLower.includes('drop') ||
      toolLower.includes('truncate')
    ) {
      return {
        action: 'prompt',
        riskLevel: 'destructive',
        reason: 'Destructive operation inferred from tool name',
      };
    }

    // Write operations
    if (
      toolLower.includes('write') ||
      toolLower.includes('create') ||
      toolLower.includes('update') ||
      toolLower.includes('insert') ||
      toolLower.includes('modify') ||
      toolLower.includes('set')
    ) {
      return {
        action: 'prompt',
        riskLevel: 'write',
        reason: 'Write operation inferred from tool name',
      };
    }

    // Read operations
    if (
      toolLower.includes('read') ||
      toolLower.includes('get') ||
      toolLower.includes('list') ||
      toolLower.includes('search') ||
      toolLower.includes('find') ||
      toolLower.includes('query')
    ) {
      return {
        action: 'allow',
        riskLevel: 'read',
        reason: 'Read operation inferred from tool name',
      };
    }

    // Default for unknown tools
    return {
      action: this.defaultAction,
      riskLevel: 'write',
      reason: 'Unknown tool type',
    };
  }

  private extractPath(args: Record<string, unknown>): string {
    const pathKeys = ['path', 'file', 'filename', 'filepath', 'directory', 'dir'];
    for (const key of pathKeys) {
      if (typeof args[key] === 'string') {
        return args[key] as string;
      }
    }
    return '';
  }

  private matchPath(path: string, pattern: string): boolean {
    // Simple glob matching
    if (pattern === '*') return true;
    if (pattern === path) return true;

    const regex = new RegExp(
      '^' +
        pattern
          .replace(/[.+^${}()|[\]\\]/g, '\\$&')
          .replace(/\*/g, '.*')
          .replace(/\?/g, '.') +
        '$'
    );
    return regex.test(path);
  }

  private policyDescription(policy: PolicyConfig): string {
    const parts: string[] = [];
    if (policy.tools) {
      const tools = Array.isArray(policy.tools) ? policy.tools : [policy.tools];
      parts.push(`tools: ${tools.join(', ')}`);
    }
    if (policy.action) {
      parts.push(`action: ${policy.action}`);
    }
    return parts.join(', ') || 'default policy';
  }

  /**
   * Clean up resources.
   */
  close(): void {
    this.stopWatching();
    this.compiledPatterns.clear();
    this.removeAllListeners();
  }
}
