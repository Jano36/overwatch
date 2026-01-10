/**
 * Tool Shadowing Detection for Overwatch
 *
 * Detects MCP tool shadowing attacks where a malicious MCP server shadows
 * legitimate tools to intercept or modify behavior.
 *
 * Detection capabilities:
 * - Schema hashing: Hash tool definitions on first connection
 * - Change detection: Alert when tool definitions change mid-session
 * - Cross-server collision: Detect same tool name across multiple servers
 * - Description analysis: Flag suspicious tool descriptions
 * - Rate limiting: Prevent DoS via excessive collision checks
 * - Metrics: Track detection events for observability
 *
 * References:
 * - Invariant Labs MCP Attack Vector
 * - CVE-2025-6514 (CVSS 9.6)
 * - OWASP LLM Top 10 2025 - LLM03 (Supply Chain Attacks)
 */

import { createHash } from 'node:crypto';

// =============================================================================
// Metrics (O-H3)
// =============================================================================

/**
 * Metrics for tool shadowing detection.
 */
export interface ShadowingMetrics {
  /** Total tools registered across all servers */
  toolsRegistered: number;
  /** Total collision checks performed */
  collisionChecks: number;
  /** Total collisions detected */
  collisionsDetected: number;
  /** Critical collisions (different schemas) */
  criticalCollisions: number;
  /** Total mutation checks performed */
  mutationChecks: number;
  /** Total mutations detected */
  mutationsDetected: number;
  /** Suspicious descriptions detected */
  suspiciousDescriptions: number;
  /** Malformed tool definitions rejected */
  malformedToolsRejected: number;
  /** Rate limit violations */
  rateLimitViolations: number;
  /** Timestamp of last reset */
  lastReset: Date;
}

/**
 * Rate limiting configuration.
 */
export interface RateLimitConfig {
  /** Maximum checks per window */
  maxChecks: number;
  /** Window size in milliseconds */
  windowMs: number;
}

/**
 * Result of a validation check.
 */
export interface ValidationResult {
  valid: boolean;
  error?: string;
}

// =============================================================================
// Types
// =============================================================================

/**
 * MCP Tool definition.
 */
export interface Tool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

/**
 * Hash record for a single tool definition.
 */
export interface ToolSchemaHash {
  /** Server that provides this tool */
  server: string;
  /** Tool name */
  toolName: string;
  /** SHA-256 hash of the tool schema */
  schemaHash: string;
  /** SHA-256 hash of the description */
  descriptionHash: string;
  /** Combined hash (schema + description) */
  combinedHash: string;
  /** Timestamp when first captured */
  capturedAt: Date;
  /** The tool definition (for comparison) */
  tool: Tool;
}

/**
 * Result of a tool shadowing check.
 */
export interface ShadowingCheckResult {
  /** Whether shadowing was detected */
  detected: boolean;
  /** Type of shadowing detected */
  type?: 'collision' | 'mutation' | 'suspicious_description';
  /** Severity level */
  severity?: 'low' | 'medium' | 'high' | 'critical';
  /** Details about the detection */
  details?: ShadowingDetails;
  /** Recommended action */
  recommendedAction?: 'allow' | 'prompt' | 'deny';
}

/**
 * Detailed information about detected shadowing.
 */
export interface ShadowingDetails {
  /** Tool name involved */
  toolName: string;
  /** Servers involved in collision (for collision detection) */
  servers?: string[];
  /** Previous hash (for mutation detection) */
  previousHash?: string;
  /** Current hash (for mutation detection) */
  currentHash?: string;
  /** Suspicious patterns found in description */
  suspiciousPatterns?: string[];
  /** Human-readable explanation */
  message: string;
}

/**
 * Aggregated shadowing report for all tools from a server.
 */
export interface ServerShadowingReport {
  /** Server name */
  server: string;
  /** Total tools analyzed */
  totalTools: number;
  /** Number of collisions detected */
  collisions: number;
  /** Number of mutations detected */
  mutations: number;
  /** Number of suspicious descriptions */
  suspiciousDescriptions: number;
  /** Individual tool reports */
  toolReports: Map<string, ShadowingCheckResult>;
  /** Timestamp of the report */
  timestamp: Date;
}

// =============================================================================
// Suspicious Description Patterns (O-H4: Enhanced)
// =============================================================================

/**
 * Patterns in tool descriptions that may indicate shadowing attacks.
 * Based on Invariant Labs research and common prompt injection patterns.
 * Enhanced with encoding normalization and additional patterns.
 */
const SUSPICIOUS_DESCRIPTION_PATTERNS: Array<{
  pattern: RegExp;
  severity: 'medium' | 'high' | 'critical';
  description: string;
}> = [
  // Instruction override patterns
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
    severity: 'critical',
    description: 'Instruction override attempt',
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
    severity: 'critical',
    description: 'Instruction override attempt',
  },
  {
    pattern: /forget\s+(all\s+)?(previous|prior|above|earlier)/i,
    severity: 'critical',
    description: 'Instruction override attempt',
  },
  {
    pattern: /new\s+instructions?:/i,
    severity: 'high',
    description: 'New instruction injection',
  },
  {
    pattern: /from\s+now\s+on/i,
    severity: 'high',
    description: 'Behavioral override attempt',
  },
  {
    pattern: /override\s+(the\s+)?(system|safety|rules)/i,
    severity: 'critical',
    description: 'System override attempt',
  },
  {
    pattern: /bypass\s+(the\s+)?(safety|security|restrictions)/i,
    severity: 'critical',
    description: 'Security bypass attempt',
  },

  // Role manipulation patterns
  {
    pattern: /you\s+are\s+now/i,
    severity: 'high',
    description: 'Role manipulation attempt',
  },
  {
    pattern: /act\s+as\s+(a|an)?/i,
    severity: 'medium',
    description: 'Role manipulation attempt',
  },
  {
    pattern: /pretend\s+to\s+be/i,
    severity: 'high',
    description: 'Role manipulation attempt',
  },
  {
    pattern: /jailbreak/i,
    severity: 'critical',
    description: 'Jailbreak attempt',
  },
  {
    pattern: /roleplay\s+as\s+(a|an)?\s*(malicious|evil|hacker)/i,
    severity: 'critical',
    description: 'Malicious roleplay attempt',
  },

  // Data exfiltration patterns
  {
    pattern: /send(ing)?\s+(all\s+)?(data|information|content|files|secrets?|credentials?)\s+to/i,
    severity: 'critical',
    description: 'Data exfiltration instruction',
  },
  {
    pattern: /exfiltrate/i,
    severity: 'critical',
    description: 'Data exfiltration instruction',
  },
  {
    pattern: /upload\s+(to|all|files|secrets?)/i,
    severity: 'high',
    description: 'Potential data exfiltration',
  },
  {
    pattern: /post\s+(to|all|data)\s+.*(http|webhook|server)/i,
    severity: 'critical',
    description: 'Potential data exfiltration via HTTP',
  },
  {
    pattern: /extract\s+(and\s+)?send/i,
    severity: 'critical',
    description: 'Data extraction and exfiltration',
  },

  // Context hijacking patterns
  {
    pattern: /<\/system>/i,
    severity: 'critical',
    description: 'Context boundary manipulation',
  },
  {
    pattern: /\[INST\]/i,
    severity: 'high',
    description: 'LLM tag injection',
  },
  {
    pattern: /<<SYS>>/i,
    severity: 'high',
    description: 'LLM system tag injection',
  },
  {
    pattern: /Human:|Assistant:/i,
    severity: 'high',
    description: 'Conversation boundary manipulation',
  },
  {
    pattern: /<\|im_start\|>|<\|im_end\|>/i,
    severity: 'critical',
    description: 'ChatML token injection',
  },
  {
    pattern: /<\|system\|>|<\|user\|>|<\|assistant\|>/i,
    severity: 'critical',
    description: 'Special token injection',
  },

  // Hidden content patterns
  {
    pattern: /<!--.*ignore.*-->/i,
    severity: 'critical',
    description: 'Hidden instruction in HTML comment',
  },
  {
    pattern: /"_comment"\s*:/i,
    severity: 'high',
    description: 'Hidden instruction in JSON comment field',
  },
  {
    pattern: /\x00|\x1b|\x7f/,
    severity: 'critical',
    description: 'Control character injection',
  },

  // Obfuscation patterns
  {
    pattern: /base64:|atob\(|btoa\(/i,
    severity: 'high',
    description: 'Encoded content reference',
  },
  {
    pattern: /eval\s*\(/i,
    severity: 'critical',
    description: 'Code evaluation attempt',
  },
  {
    pattern: /exec\s*\(/i,
    severity: 'critical',
    description: 'Command execution attempt',
  },

  // Privilege escalation patterns
  {
    pattern: /sudo|administrator|root\s+access/i,
    severity: 'high',
    description: 'Privilege escalation reference',
  },
  {
    pattern: /disable\s+(the\s+)?(security|safety|filters?)/i,
    severity: 'critical',
    description: 'Security disable attempt',
  },

  // Credential theft patterns
  {
    pattern: /(api[_\s]?key|password|secret|token|credential)s?\s*(are|is|:)/i,
    severity: 'high',
    description: 'Credential reference in description',
  },
];

/**
 * Normalizes text for pattern matching (O-H4).
 * Handles common obfuscation techniques.
 */
function normalizeForPatternMatching(text: string): string {
  let normalized = text;

  // Decode URL encoding
  try {
    normalized = decodeURIComponent(normalized.replace(/\+/g, ' '));
  } catch {
    // Keep original if decoding fails
  }

  // Decode HTML entities
  const htmlEntities: Record<string, string> = {
    '&lt;': '<',
    '&gt;': '>',
    '&amp;': '&',
    '&quot;': '"',
    '&#39;': "'",
    '&apos;': "'",
    '&nbsp;': ' ',
  };
  for (const [entity, char] of Object.entries(htmlEntities)) {
    normalized = normalized.replace(new RegExp(entity, 'gi'), char);
  }

  // Normalize Unicode to ASCII equivalents
  normalized = normalized.normalize('NFKC');

  // Collapse multiple whitespace
  normalized = normalized.replace(/\s+/g, ' ');

  return normalized;
}

// =============================================================================
// Tool Shadowing Detector
// =============================================================================

/**
 * Detects tool shadowing attacks in MCP environments.
 *
 * Maintains a registry of tool schema hashes and detects:
 * - Tool name collisions across servers
 * - Mid-session tool definition mutations
 * - Suspicious content in tool descriptions
 *
 * @example
 * ```typescript
 * const detector = new ToolShadowingDetector();
 *
 * // Register tools when server connects
 * const report = detector.registerServerTools('myserver', tools);
 *
 * // Check for shadowing on subsequent calls
 * const result = detector.checkTool('myserver', 'read_file');
 *
 * // Verify tool hasn't changed mid-session
 * const mutationCheck = detector.checkForMutation('myserver', currentTool);
 * ```
 */
export class ToolShadowingDetector {
  // ---------------------------------------------------------------------------
  // Private State
  // ---------------------------------------------------------------------------

  /**
   * Map of server -> (tool name -> hash record)
   */
  private toolHashes: Map<string, Map<string, ToolSchemaHash>> = new Map();

  /**
   * Map of tool name -> list of servers that provide it
   */
  private toolToServers: Map<string, Set<string>> = new Map();

  /**
   * Set of known collisions (to avoid repeated alerts)
   */
  private knownCollisions: Set<string> = new Set();

  /**
   * Metrics for observability (O-H3)
   */
  private metrics: ShadowingMetrics = this.createInitialMetrics();

  /**
   * Rate limiting state (O-H2)
   */
  private rateLimitState: Map<string, { count: number; windowStart: number }> = new Map();

  /**
   * Rate limit configuration (O-H2)
   */
  private rateLimitConfig: RateLimitConfig = {
    maxChecks: 1000,
    windowMs: 60000, // 1 minute
  };

  /**
   * Creates initial metrics object
   */
  private createInitialMetrics(): ShadowingMetrics {
    return {
      toolsRegistered: 0,
      collisionChecks: 0,
      collisionsDetected: 0,
      criticalCollisions: 0,
      mutationChecks: 0,
      mutationsDetected: 0,
      suspiciousDescriptions: 0,
      malformedToolsRejected: 0,
      rateLimitViolations: 0,
      lastReset: new Date(),
    };
  }

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  /**
   * Configures rate limiting (O-H2)
   */
  setRateLimitConfig(config: Partial<RateLimitConfig>): void {
    this.rateLimitConfig = { ...this.rateLimitConfig, ...config };
  }

  /**
   * Gets current metrics (O-H3)
   */
  getMetrics(): ShadowingMetrics {
    return { ...this.metrics };
  }

  /**
   * Resets metrics (O-H3)
   */
  resetMetrics(): void {
    this.metrics = this.createInitialMetrics();
  }

  // ---------------------------------------------------------------------------
  // Rate Limiting (O-H2)
  // ---------------------------------------------------------------------------

  /**
   * Checks if rate limit is exceeded for a server
   */
  private checkRateLimit(server: string): boolean {
    const now = Date.now();
    const state = this.rateLimitState.get(server);

    if (!state || now - state.windowStart > this.rateLimitConfig.windowMs) {
      // New window
      this.rateLimitState.set(server, { count: 1, windowStart: now });
      return false;
    }

    if (state.count >= this.rateLimitConfig.maxChecks) {
      this.metrics.rateLimitViolations++;
      return true;
    }

    state.count++;
    return false;
  }

  // ---------------------------------------------------------------------------
  // Tool Validation (O-H1)
  // ---------------------------------------------------------------------------

  /**
   * Validates a tool definition for correctness (O-H1)
   */
  validateTool(tool: unknown): ValidationResult {
    // Check if tool is an object
    if (!tool || typeof tool !== 'object') {
      return { valid: false, error: 'Tool must be a non-null object' };
    }

    const t = tool as Record<string, unknown>;

    // Check for required name field
    if (typeof t.name !== 'string') {
      return { valid: false, error: 'Tool must have a string name property' };
    }

    // Name must be non-empty
    if (t.name.trim().length === 0) {
      return { valid: false, error: 'Tool name cannot be empty' };
    }

    // Name length limit (prevent DoS via long names)
    if (t.name.length > 256) {
      return { valid: false, error: 'Tool name exceeds maximum length (256)' };
    }

    // Description length limit
    if (typeof t.description === 'string' && t.description.length > 10000) {
      return { valid: false, error: 'Tool description exceeds maximum length (10000)' };
    }

    // Validate inputSchema if present
    if (t.inputSchema !== undefined) {
      if (typeof t.inputSchema !== 'object') {
        return { valid: false, error: 'inputSchema must be an object' };
      }

      // Check for excessively deep nesting (prevent DoS)
      if (this.getObjectDepth(t.inputSchema) > 20) {
        return { valid: false, error: 'inputSchema nesting exceeds maximum depth (20)' };
      }
    }

    return { valid: true };
  }

  /**
   * Gets the maximum depth of nested objects
   */
  private getObjectDepth(obj: unknown, currentDepth = 0): number {
    if (currentDepth > 25) return currentDepth; // Safety limit

    if (!obj || typeof obj !== 'object') {
      return currentDepth;
    }

    if (Array.isArray(obj)) {
      let maxDepth = currentDepth;
      for (const item of obj) {
        maxDepth = Math.max(maxDepth, this.getObjectDepth(item, currentDepth + 1));
      }
      return maxDepth;
    }

    let maxDepth = currentDepth;
    for (const value of Object.values(obj as Record<string, unknown>)) {
      maxDepth = Math.max(maxDepth, this.getObjectDepth(value, currentDepth + 1));
    }
    return maxDepth;
  }

  // ---------------------------------------------------------------------------
  // Schema Hashing
  // ---------------------------------------------------------------------------

  /**
   * Recursively sorts object keys for consistent hashing.
   */
  private sortObject(obj: unknown): unknown {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sortObject(item));
    }

    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    for (const key of keys) {
      sorted[key] = this.sortObject((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }

  /**
   * Computes SHA-256 hash of a tool's schema.
   */
  private hashSchema(tool: Tool): string {
    // Normalize and hash the input schema with consistent key ordering
    const sortedSchema = this.sortObject(tool.inputSchema ?? {});
    const schemaStr = JSON.stringify(sortedSchema);
    return createHash('sha256').update(schemaStr).digest('hex');
  }

  /**
   * Computes SHA-256 hash of a tool's description.
   */
  private hashDescription(tool: Tool): string {
    return createHash('sha256').update(tool.description ?? '').digest('hex');
  }

  /**
   * Computes combined hash of name, schema, and description.
   */
  private computeCombinedHash(tool: Tool): string {
    const combined = `${tool.name}:${this.hashSchema(tool)}:${this.hashDescription(tool)}`;
    return createHash('sha256').update(combined).digest('hex');
  }

  /**
   * Creates a hash record for a tool.
   */
  private createHashRecord(server: string, tool: Tool): ToolSchemaHash {
    return {
      server,
      toolName: tool.name,
      schemaHash: this.hashSchema(tool),
      descriptionHash: this.hashDescription(tool),
      combinedHash: this.computeCombinedHash(tool),
      capturedAt: new Date(),
      tool,
    };
  }

  // ---------------------------------------------------------------------------
  // Tool Registration
  // ---------------------------------------------------------------------------

  /**
   * Registers all tools from a server and checks for shadowing.
   *
   * Should be called when a server first connects and provides its tool list.
   *
   * @param server - Server name
   * @param tools - List of tools from the server
   * @returns Report with any detected shadowing issues
   */
  registerServerTools(server: string, tools: Tool[]): ServerShadowingReport {
    const report: ServerShadowingReport = {
      server,
      totalTools: tools.length,
      collisions: 0,
      mutations: 0,
      suspiciousDescriptions: 0,
      toolReports: new Map(),
      timestamp: new Date(),
    };

    // Check rate limit (O-H2)
    if (this.checkRateLimit(server)) {
      // Rate limited - return empty report
      return report;
    }

    // Initialize server map if needed
    if (!this.toolHashes.has(server)) {
      this.toolHashes.set(server, new Map());
    }
    const serverHashes = this.toolHashes.get(server)!;

    for (const tool of tools) {
      // Validate tool (O-H1)
      const validation = this.validateTool(tool);
      if (!validation.valid) {
        this.metrics.malformedToolsRejected++;
        // Add to report as a warning
        report.toolReports.set(tool?.name ?? '<invalid>', {
          detected: true,
          type: 'suspicious_description',
          severity: 'medium',
          details: {
            toolName: tool?.name ?? '<invalid>',
            message: `Malformed tool rejected: ${validation.error}`,
          },
          recommendedAction: 'deny',
        });
        continue;
      }

      // Create hash record
      const hashRecord = this.createHashRecord(server, tool);
      serverHashes.set(tool.name, hashRecord);

      // Track metrics (O-H3)
      this.metrics.toolsRegistered++;

      // Track which servers provide this tool
      if (!this.toolToServers.has(tool.name)) {
        this.toolToServers.set(tool.name, new Set());
      }
      this.toolToServers.get(tool.name)!.add(server);

      // Check for suspicious description
      const descriptionCheck = this.checkSuspiciousDescription(tool);
      if (descriptionCheck.detected) {
        report.suspiciousDescriptions++;
        this.metrics.suspiciousDescriptions++;
        report.toolReports.set(tool.name, descriptionCheck);
      }

      // Check for collisions
      const collisionCheck = this.checkCollision(server, tool.name);
      if (collisionCheck.detected) {
        report.collisions++;
        this.metrics.collisionsDetected++;
        if (collisionCheck.severity === 'critical') {
          this.metrics.criticalCollisions++;
        }
        // Only update report if this is a new or more severe issue
        const existing = report.toolReports.get(tool.name);
        if (
          !existing ||
          this.severityToNumber(collisionCheck.severity!) > this.severityToNumber(existing.severity!)
        ) {
          report.toolReports.set(tool.name, collisionCheck);
        }
      }
    }

    return report;
  }

  /**
   * Converts severity to numeric value for comparison.
   */
  private severityToNumber(severity: 'low' | 'medium' | 'high' | 'critical'): number {
    switch (severity) {
      case 'low':
        return 1;
      case 'medium':
        return 2;
      case 'high':
        return 3;
      case 'critical':
        return 4;
    }
  }

  // ---------------------------------------------------------------------------
  // Collision Detection
  // ---------------------------------------------------------------------------

  /**
   * Checks if a tool name is provided by multiple servers.
   *
   * @param server - Current server name
   * @param toolName - Tool name to check
   * @returns Check result with collision details if detected
   */
  checkCollision(server: string, toolName: string): ShadowingCheckResult {
    // Track metric (O-H3)
    this.metrics.collisionChecks++;

    const servers = this.toolToServers.get(toolName);

    if (!servers || servers.size <= 1) {
      return { detected: false };
    }

    // Tool exists on multiple servers
    const otherServers = Array.from(servers).filter((s) => s !== server);
    const collisionKey = `${toolName}:${Array.from(servers).sort().join(',')}`;

    // Check if schemas are identical (legitimate shared tool) or different (shadowing)
    const currentHash = this.toolHashes.get(server)?.get(toolName)?.combinedHash;
    const otherHashes = otherServers.map((s) => this.toolHashes.get(s)?.get(toolName)?.combinedHash);

    // All hashes match - probably legitimate
    const allMatch = otherHashes.every((h) => h === currentHash);

    if (allMatch) {
      // Same schema - could be legitimate but still worth noting
      if (!this.knownCollisions.has(collisionKey)) {
        this.knownCollisions.add(collisionKey);
      }
      return {
        detected: true,
        type: 'collision',
        severity: 'low',
        details: {
          toolName,
          servers: Array.from(servers),
          message: `Tool "${toolName}" is provided by multiple servers with identical schemas. This may be intentional.`,
        },
        recommendedAction: 'allow',
      };
    }

    // Different schemas - potential shadowing attack
    if (!this.knownCollisions.has(collisionKey)) {
      this.knownCollisions.add(collisionKey);
    }

    return {
      detected: true,
      type: 'collision',
      severity: 'critical',
      details: {
        toolName,
        servers: Array.from(servers),
        message: `ALERT: Tool "${toolName}" is provided by multiple servers with DIFFERENT schemas. This may indicate a tool shadowing attack.`,
      },
      recommendedAction: 'deny',
    };
  }

  // ---------------------------------------------------------------------------
  // Mutation Detection
  // ---------------------------------------------------------------------------

  /**
   * Checks if a tool's definition has changed since registration.
   *
   * Should be called before forwarding tool calls to detect mid-session attacks.
   *
   * @param server - Server name
   * @param tool - Current tool definition
   * @returns Check result with mutation details if detected
   */
  checkForMutation(server: string, tool: Tool): ShadowingCheckResult {
    // Track metric (O-H3)
    this.metrics.mutationChecks++;

    const serverHashes = this.toolHashes.get(server);
    if (!serverHashes) {
      // Server not registered - this is the first time we're seeing it
      return { detected: false };
    }

    const originalHash = serverHashes.get(tool.name);
    if (!originalHash) {
      // Tool not previously registered - could be new tool added mid-session
      this.metrics.mutationsDetected++;
      return {
        detected: true,
        type: 'mutation',
        severity: 'high',
        details: {
          toolName: tool.name,
          message: `Tool "${tool.name}" appeared mid-session. This could indicate dynamic tool injection.`,
        },
        recommendedAction: 'prompt',
      };
    }

    // Compute current hash
    const currentHash = this.computeCombinedHash(tool);

    if (currentHash === originalHash.combinedHash) {
      return { detected: false };
    }

    // Schema has changed mid-session
    this.metrics.mutationsDetected++;
    return {
      detected: true,
      type: 'mutation',
      severity: 'critical',
      details: {
        toolName: tool.name,
        previousHash: originalHash.combinedHash,
        currentHash,
        message: `CRITICAL: Tool "${tool.name}" schema has changed mid-session. This may indicate an active attack.`,
      },
      recommendedAction: 'deny',
    };
  }

  // ---------------------------------------------------------------------------
  // Description Analysis
  // ---------------------------------------------------------------------------

  /**
   * Analyzes a tool's description for suspicious patterns.
   * Uses encoding normalization for obfuscation resistance (O-H4).
   *
   * @param tool - Tool to analyze
   * @returns Check result with suspicious patterns if detected
   */
  checkSuspiciousDescription(tool: Tool): ShadowingCheckResult {
    const rawDescription = tool.description ?? '';
    // Normalize for obfuscation resistance (O-H4)
    const normalizedDescription = normalizeForPatternMatching(rawDescription);

    const foundPatterns: Array<{ pattern: string; severity: 'medium' | 'high' | 'critical' }> = [];
    let maxSeverity: 'low' | 'medium' | 'high' | 'critical' = 'low';

    for (const { pattern, severity, description: patternDesc } of SUSPICIOUS_DESCRIPTION_PATTERNS) {
      // Check both raw and normalized descriptions
      if (pattern.test(rawDescription) || pattern.test(normalizedDescription)) {
        foundPatterns.push({ pattern: patternDesc, severity });
        if (this.severityToNumber(severity) > this.severityToNumber(maxSeverity)) {
          maxSeverity = severity;
        }
      }
    }

    if (foundPatterns.length === 0) {
      return { detected: false };
    }

    // Determine recommended action based on severity
    let recommendedAction: 'allow' | 'prompt' | 'deny';
    switch (maxSeverity) {
      case 'critical':
        recommendedAction = 'deny';
        break;
      case 'high':
        recommendedAction = 'prompt';
        break;
      default:
        recommendedAction = 'prompt';
    }

    return {
      detected: true,
      type: 'suspicious_description',
      severity: maxSeverity,
      details: {
        toolName: tool.name,
        suspiciousPatterns: foundPatterns.map((p) => p.pattern),
        message: `Tool "${tool.name}" description contains suspicious patterns: ${foundPatterns.map((p) => p.pattern).join(', ')}`,
      },
      recommendedAction,
    };
  }

  // ---------------------------------------------------------------------------
  // Query Methods
  // ---------------------------------------------------------------------------

  /**
   * Gets the hash record for a specific tool.
   */
  getToolHash(server: string, toolName: string): ToolSchemaHash | undefined {
    return this.toolHashes.get(server)?.get(toolName);
  }

  /**
   * Gets all servers that provide a specific tool.
   */
  getServersForTool(toolName: string): string[] {
    return Array.from(this.toolToServers.get(toolName) ?? []);
  }

  /**
   * Gets all registered tools for a server.
   */
  getServerTools(server: string): ToolSchemaHash[] {
    const serverHashes = this.toolHashes.get(server);
    return serverHashes ? Array.from(serverHashes.values()) : [];
  }

  /**
   * Gets all detected collisions.
   */
  getAllCollisions(): Array<{ toolName: string; servers: string[]; severity: 'low' | 'critical' }> {
    const collisions: Array<{ toolName: string; servers: string[]; severity: 'low' | 'critical' }> = [];

    for (const [toolName, servers] of this.toolToServers) {
      if (servers.size > 1) {
        // Check if schemas match
        const hashes = new Set<string>();
        for (const server of servers) {
          const hash = this.toolHashes.get(server)?.get(toolName)?.combinedHash;
          if (hash) hashes.add(hash);
        }

        collisions.push({
          toolName,
          servers: Array.from(servers),
          severity: hashes.size === 1 ? 'low' : 'critical',
        });
      }
    }

    return collisions;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Clears all registered tools for a server.
   * Should be called when a server disconnects.
   */
  clearServer(server: string): void {
    const serverHashes = this.toolHashes.get(server);
    if (serverHashes) {
      // Remove server from tool-to-server mappings
      for (const toolName of serverHashes.keys()) {
        this.toolToServers.get(toolName)?.delete(server);
        if (this.toolToServers.get(toolName)?.size === 0) {
          this.toolToServers.delete(toolName);
        }
      }
      this.toolHashes.delete(server);
    }
  }

  /**
   * Clears all state. Useful for testing.
   */
  clear(): void {
    this.toolHashes.clear();
    this.toolToServers.clear();
    this.knownCollisions.clear();
  }
}

// =============================================================================
// Singleton Instance
// =============================================================================

/**
 * Global tool shadowing detector instance.
 * Shared across all proxy instances.
 */
export const toolShadowingDetector = new ToolShadowingDetector();
