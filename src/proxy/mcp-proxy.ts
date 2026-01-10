import { spawn, type ChildProcess } from 'child_process';
import { EventEmitter } from 'events';
import {
  MCPTransport,
  type JSONRPCMessage,
  type JSONRPCRequest,
  isRequest,
  isResponse,
  createErrorResponse,
} from './transport.js';
import { PolicyEngine, type PolicyDecision } from './policy-engine.js';
import type { OverwatchConfig, ServerConfig } from '../config/types.js';
import type { ApprovalHandler, ApprovalRequest } from '../approval/types.js';
import type { AuditEntry } from '../audit/logger.js';

// =============================================================================
// JSON-RPC Error Codes
// =============================================================================

/**
 * JSON-RPC error codes used by Overwatch.
 * These follow the JSON-RPC 2.0 specification for server errors (-32000 to -32099).
 */
export const JSONRPCErrorCodes = {
  /** Tool call denied by policy */
  TOOL_DENIED: -32001,
  /** Upstream server unavailable */
  UPSTREAM_UNAVAILABLE: -32002,
  /** Request timeout */
  REQUEST_TIMEOUT: -32003,
  /** Request too large */
  REQUEST_TOO_LARGE: -32004,
  /** Circuit breaker open */
  CIRCUIT_BREAKER_OPEN: -32005,
  /** Server shutting down */
  SERVER_SHUTTING_DOWN: -32006,
} as const;

// =============================================================================
// Environment Variable Filtering
// =============================================================================

/**
 * Environment variable patterns to filter when spawning child processes.
 * These patterns match sensitive credentials that should not be inherited.
 */
const SENSITIVE_ENV_PATTERNS: RegExp[] = [
  // API keys and tokens
  /^(ANTHROPIC|OPENAI|CLAUDE|GPT|HUGGINGFACE|COHERE|AI21|MISTRAL).*(_KEY|_TOKEN|_SECRET)$/i,
  /^(AWS|AZURE|GCP|GOOGLE|DIGITALOCEAN|HEROKU|VERCEL|NETLIFY).*(_KEY|_SECRET|_TOKEN|_CREDENTIALS?)$/i,
  /^(GITHUB|GITLAB|BITBUCKET|NPM|PYPI|RUBYGEMS).*(_TOKEN|_KEY|_SECRET)$/i,
  /^(STRIPE|PAYPAL|BRAINTREE|SQUARE).*(_KEY|_SECRET)$/i,
  /^(SENDGRID|MAILGUN|POSTMARK|SES|TWILIO).*(_KEY|_SECRET|_TOKEN|_SID)$/i,
  /^(SLACK|DISCORD|TELEGRAM).*(_TOKEN|_SECRET|_KEY|_WEBHOOK)$/i,
  /^(DATABASE|DB|MONGO|POSTGRES|MYSQL|REDIS).*(_URL|_PASSWORD|_SECRET|_KEY)$/i,
  /^(JWT|SESSION|AUTH).*(_SECRET|_KEY|_TOKEN)$/i,
  // Common secret patterns
  /^.*_(SECRET|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_TOKEN|REFRESH_TOKEN)$/i,
  /^(SECRET|PASSWORD|CREDENTIAL|PRIVATE)_/i,
];

/**
 * Filters sensitive environment variables from the parent process.
 * Returns a sanitized copy of process.env suitable for child processes.
 *
 * @param additionalEnv - Additional environment variables to include
 * @returns Filtered environment variables
 */
function filterSensitiveEnv(additionalEnv: Record<string, string> = {}): NodeJS.ProcessEnv {
  const filtered: NodeJS.ProcessEnv = {};

  for (const [key, value] of Object.entries(process.env)) {
    // Skip sensitive variables
    const isSensitive = SENSITIVE_ENV_PATTERNS.some((pattern) => pattern.test(key));
    if (!isSensitive) {
      filtered[key] = value;
    }
  }

  // Merge with additional env (these are intentionally provided, so include them)
  return { ...filtered, ...additionalEnv };
}

// =============================================================================
// Circuit Breaker (O-H7)
// =============================================================================

/**
 * Circuit breaker states
 */
export type CircuitBreakerState = 'closed' | 'open' | 'half-open';

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  /** Number of failures before opening circuit */
  failureThreshold: number;
  /** Time in ms to wait before trying half-open */
  resetTimeout: number;
  /** Number of successful requests to close circuit in half-open */
  successThreshold: number;
}

/**
 * Circuit breaker for upstream failure protection
 */
export class CircuitBreaker {
  private state: CircuitBreakerState = 'closed';
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private config: CircuitBreakerConfig;

  constructor(config?: Partial<CircuitBreakerConfig>) {
    this.config = {
      failureThreshold: config?.failureThreshold ?? 5,
      resetTimeout: config?.resetTimeout ?? 60000,
      successThreshold: config?.successThreshold ?? 2,
    };
  }

  /**
   * Check if request should be allowed
   */
  canExecute(): boolean {
    if (this.state === 'closed') {
      return true;
    }

    if (this.state === 'open') {
      // Check if reset timeout has passed
      if (Date.now() - this.lastFailureTime >= this.config.resetTimeout) {
        this.state = 'half-open';
        this.successCount = 0;
        return true;
      }
      return false;
    }

    // half-open: allow limited requests
    return true;
  }

  /**
   * Record a successful request
   */
  recordSuccess(): void {
    if (this.state === 'half-open') {
      this.successCount++;
      if (this.successCount >= this.config.successThreshold) {
        this.state = 'closed';
        this.failureCount = 0;
      }
    } else if (this.state === 'closed') {
      this.failureCount = 0;
    }
  }

  /**
   * Record a failed request
   */
  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === 'half-open') {
      this.state = 'open';
    } else if (
      this.state === 'closed' &&
      this.failureCount >= this.config.failureThreshold
    ) {
      this.state = 'open';
    }
  }

  /**
   * Get current state
   */
  getState(): CircuitBreakerState {
    return this.state;
  }

  /**
   * Reset circuit breaker
   */
  reset(): void {
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
  }
}

// Proxy Configuration

export interface MCPProxyOptions {
  serverName: string;
  serverConfig: ServerConfig;
  overwatchConfig: OverwatchConfig;
  approvalHandler: ApprovalHandler;
  onAuditEntry?: (entry: AuditEntry) => void;
  failMode?: 'open' | 'closed' | 'readonly';
  /** Request timeout in milliseconds (O-H5) */
  requestTimeout?: number;
  /** Maximum request/response size in bytes (O-H10) */
  maxMessageSize?: number;
  /** Circuit breaker configuration (O-H7) */
  circuitBreakerConfig?: Partial<CircuitBreakerConfig>;
  /** Enable connection recovery (O-H8) */
  enableRecovery?: boolean;
  /** Maximum recovery attempts (O-H8) */
  maxRecoveryAttempts?: number;
}

export class MCPProxy extends EventEmitter {
  private upstreamProcess: ChildProcess | null = null;
  private upstreamTransport: MCPTransport | null = null;
  private clientTransport: MCPTransport;
  private policyEngine: PolicyEngine;
  private pendingRequests: Map<string | number, {
    request: JSONRPCRequest;
    startTime: number;
    timeoutHandle?: ReturnType<typeof setTimeout>;
  }> = new Map();
  private running = false;
  private sessionId: string;

  // Hardening features (O-H5 through O-H10)
  private circuitBreaker: CircuitBreaker;
  private requestTimeout: number;
  private maxMessageSize: number;
  private enableRecovery: boolean;
  private maxRecoveryAttempts: number;
  private recoveryAttempts = 0;
  private timeoutCheckInterval: ReturnType<typeof setInterval> | null = null;
  private isShuttingDown = false;

  // Metrics
  private metrics = {
    requestsTotal: 0,
    requestsTimedOut: 0,
    requestsFailed: 0,
    circuitBreakerTrips: 0,
    recoveryAttempts: 0,
  };

  constructor(private options: MCPProxyOptions) {
    super();
    this.policyEngine = new PolicyEngine(options.overwatchConfig);
    this.sessionId = crypto.randomUUID();

    // Initialize hardening features (O-H5 through O-H10)
    this.circuitBreaker = new CircuitBreaker(options.circuitBreakerConfig);
    this.requestTimeout = options.requestTimeout ?? 30000; // Default 30s (O-H5)
    this.maxMessageSize = options.maxMessageSize ?? 10 * 1024 * 1024; // Default 10MB (O-H10)
    this.enableRecovery = options.enableRecovery ?? true;
    this.maxRecoveryAttempts = options.maxRecoveryAttempts ?? 5;

    // Create transport for client (stdin/stdout)
    this.clientTransport = new MCPTransport(
      process.stdin,
      process.stdout,
      'client'
    );
  }

  async start(): Promise<void> {
    this.running = true;
    this.isShuttingDown = false;

    // Spawn upstream MCP server
    const { command, args = [], env = {} } = this.options.serverConfig;

    this.upstreamProcess = spawn(command, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: filterSensitiveEnv(env),
    });

    if (!this.upstreamProcess.stdin || !this.upstreamProcess.stdout) {
      throw new Error('Failed to create upstream process pipes');
    }

    // Create transport for upstream
    this.upstreamTransport = new MCPTransport(
      this.upstreamProcess.stdout,
      this.upstreamProcess.stdin,
      'upstream'
    );

    // Handle upstream errors
    this.upstreamProcess.on('error', (error) => {
      this.circuitBreaker.recordFailure();
      this.emit('error', error);
      this.handleUpstreamFailure();
    });

    this.upstreamProcess.on('exit', (code, signal) => {
      if (this.running && !this.isShuttingDown) {
        this.circuitBreaker.recordFailure();
        this.emit('upstream-exit', { code, signal });
        this.handleUpstreamFailure();
      }
    });

    // Forward stderr to our stderr
    this.upstreamProcess.stderr?.pipe(process.stderr);

    // Set up message handlers
    this.setupMessageHandlers();

    // Start timeout cleanup interval (O-H6)
    this.startTimeoutChecker();

    // Reset recovery attempts on successful start
    this.recoveryAttempts = 0;

    this.emit('started', { serverName: this.options.serverName });
  }

  /**
   * Start periodic timeout checker (O-H6)
   */
  private startTimeoutChecker(): void {
    if (this.timeoutCheckInterval) {
      clearInterval(this.timeoutCheckInterval);
    }

    this.timeoutCheckInterval = setInterval(() => {
      this.cleanupTimedOutRequests();
    }, 5000); // Check every 5 seconds
  }

  /**
   * Cleanup requests that have timed out (O-H6)
   */
  private cleanupTimedOutRequests(): void {
    const now = Date.now();

    for (const [id, pending] of this.pendingRequests) {
      if (now - pending.startTime >= this.requestTimeout) {
        // Clear individual timeout if exists
        if (pending.timeoutHandle) {
          clearTimeout(pending.timeoutHandle);
        }

        // Send timeout error to client
        const response = createErrorResponse(
          id,
          JSONRPCErrorCodes.REQUEST_TIMEOUT,
          `Request timed out after ${this.requestTimeout}ms`
        );
        this.clientTransport.send(response);

        // Update metrics
        this.metrics.requestsTimedOut++;
        this.circuitBreaker.recordFailure();

        this.pendingRequests.delete(id);

        this.logAudit({
          tool: pending.request.method,
          decision: 'denied',
          error: 'Request timeout',
          riskLevel: 'write',
        } as AuditEntry);

        this.emit('request-timeout', { id, request: pending.request });
      }
    }
  }

  private setupMessageHandlers(): void {
    // Handle messages from client
    this.clientTransport.on('message', async (msg: JSONRPCMessage) => {
      await this.handleClientMessage(msg);
    });

    this.clientTransport.on('close', () => {
      this.shutdown();
    });

    // Handle messages from upstream
    this.upstreamTransport?.on('message', (msg: JSONRPCMessage) => {
      this.handleUpstreamMessage(msg);
    });

    this.upstreamTransport?.on('close', () => {
      this.handleUpstreamFailure();
    });
  }

  private async handleClientMessage(msg: JSONRPCMessage): Promise<void> {
    // Check message size limit (O-H10)
    const msgSize = JSON.stringify(msg).length;
    if (msgSize > this.maxMessageSize) {
      if (isRequest(msg) && msg.id) {
        const response = createErrorResponse(
          msg.id,
          JSONRPCErrorCodes.REQUEST_TOO_LARGE,
          `Request too large: ${msgSize} bytes exceeds limit of ${this.maxMessageSize} bytes`
        );
        this.clientTransport.send(response);
      }
      return;
    }

    // Check circuit breaker (O-H7)
    if (!this.circuitBreaker.canExecute()) {
      if (isRequest(msg) && msg.id) {
        const response = createErrorResponse(
          msg.id,
          JSONRPCErrorCodes.CIRCUIT_BREAKER_OPEN,
          'Service temporarily unavailable (circuit breaker open)'
        );
        this.clientTransport.send(response);
        this.metrics.circuitBreakerTrips++;
      }
      return;
    }

    this.metrics.requestsTotal++;

    if (!isRequest(msg)) {
      // Forward notifications directly
      this.upstreamTransport?.send(msg);
      return;
    }

    // Check if this is a tool call that needs interception
    if (msg.method === 'tools/call') {
      await this.handleToolCall(msg);
    } else {
      // Forward non-tool requests directly with timeout tracking (O-H5)
      const startTime = Date.now();
      const timeoutHandle = setTimeout(() => {
        if (this.pendingRequests.has(msg.id!)) {
          this.pendingRequests.delete(msg.id!);
          const response = createErrorResponse(
            msg.id!,
            JSONRPCErrorCodes.REQUEST_TIMEOUT,
            `Request timed out after ${this.requestTimeout}ms`
          );
          this.clientTransport.send(response);
          this.metrics.requestsTimedOut++;
          this.circuitBreaker.recordFailure();
        }
      }, this.requestTimeout);

      this.pendingRequests.set(msg.id!, {
        request: msg,
        startTime,
        timeoutHandle,
      });
      this.upstreamTransport?.send(msg);
    }
  }

  private async handleToolCall(request: JSONRPCRequest): Promise<void> {
    const params = request.params as {
      name: string;
      arguments?: Record<string, unknown>;
    };

    const toolName = params.name;
    const toolArgs = params.arguments || {};

    // Evaluate policy
    const decision = this.policyEngine.evaluate(
      this.options.serverName,
      toolName,
      toolArgs
    );

    // Log the request
    const auditEntry: Partial<AuditEntry> = {
      server: this.options.serverName,
      tool: toolName,
      args: toolArgs,
      riskLevel: decision.riskLevel,
      sessionId: this.sessionId,
    };

    if (decision.action === 'deny') {
      // Deny immediately
      const response = createErrorResponse(
        request.id!,
        JSONRPCErrorCodes.TOOL_DENIED,
        `Tool call denied: ${decision.reason}`,
        { riskLevel: decision.riskLevel }
      );
      this.clientTransport.send(response);

      this.logAudit({
        ...auditEntry,
        decision: 'denied',
        error: decision.reason,
      } as AuditEntry);
      return;
    }

    if (decision.action === 'prompt') {
      // Request user approval
      const approved = await this.requestApproval(toolName, toolArgs, decision);

      if (!approved) {
        const response = createErrorResponse(
          request.id!,
          JSONRPCErrorCodes.TOOL_DENIED,
          'Tool call denied by user',
          { riskLevel: decision.riskLevel }
        );
        this.clientTransport.send(response);

        this.logAudit({
          ...auditEntry,
          decision: 'denied',
          error: 'User denied',
        } as AuditEntry);
        return;
      }
    }

    // Allow - forward to upstream with timeout tracking (O-H5)
    const startTime = Date.now();
    const timeoutHandle = setTimeout(() => {
      if (this.pendingRequests.has(request.id!)) {
        this.pendingRequests.delete(request.id!);
        const response = createErrorResponse(
          request.id!,
          JSONRPCErrorCodes.REQUEST_TIMEOUT,
          `Tool call timed out after ${this.requestTimeout}ms`
        );
        this.clientTransport.send(response);
        this.metrics.requestsTimedOut++;
        this.circuitBreaker.recordFailure();
        this.logAudit({
          ...auditEntry,
          decision: 'denied',
          error: 'Timeout',
        } as AuditEntry);
      }
    }, this.requestTimeout);

    this.pendingRequests.set(request.id!, { request, startTime, timeoutHandle });
    this.upstreamTransport?.send(request);

    this.logAudit({
      ...auditEntry,
      decision: 'allowed',
    } as AuditEntry);
  }

  private async requestApproval(
    tool: string,
    args: Record<string, unknown>,
    decision: PolicyDecision
  ): Promise<boolean> {
    const request: ApprovalRequest = {
      id: crypto.randomUUID(),
      server: this.options.serverName,
      tool,
      args,
      riskLevel: decision.riskLevel,
      reason: decision.reason,
      timestamp: new Date(),
    };

    try {
      const response = await this.options.approvalHandler.requestApproval(request);
      return response.approved;
    } catch (error) {
      // On error, use fail mode to decide
      const failMode = this.options.failMode || 'closed';
      if (failMode === 'open') {
        return true;
      }
      return false;
    }
  }

  private handleUpstreamMessage(msg: JSONRPCMessage): void {
    // Check message size limit (O-H10)
    const msgSize = JSON.stringify(msg).length;
    if (msgSize > this.maxMessageSize) {
      this.emit('message-too-large', { size: msgSize, limit: this.maxMessageSize });
      // Still forward but log warning
    }

    if (isResponse(msg) && this.pendingRequests.has(msg.id)) {
      const pending = this.pendingRequests.get(msg.id)!;

      // Clear timeout (O-H5)
      if (pending.timeoutHandle) {
        clearTimeout(pending.timeoutHandle);
      }

      this.pendingRequests.delete(msg.id);

      // Record success for circuit breaker (O-H7)
      this.circuitBreaker.recordSuccess();
    }

    // Forward to client
    this.clientTransport.send(msg);
  }

  private handleUpstreamFailure(): void {
    const failMode = this.options.failMode || 'closed';

    // Clear pending request timeouts (O-H6)
    for (const [id, pending] of this.pendingRequests) {
      if (pending.timeoutHandle) {
        clearTimeout(pending.timeoutHandle);
      }

      if (failMode === 'closed') {
        const response = createErrorResponse(
          id,
          JSONRPCErrorCodes.UPSTREAM_UNAVAILABLE,
          'Upstream server unavailable'
        );
        this.clientTransport.send(response);
      }
    }
    this.pendingRequests.clear();
    this.metrics.requestsFailed++;

    if (failMode === 'closed') {
      this.emit('error', new Error('Upstream server failed'));
    } else if (failMode === 'readonly') {
      this.emit('warning', 'Upstream failed, operating in readonly mode');
    }
    // failMode === 'open': continue operating (risky)

    // Attempt recovery with exponential backoff (O-H8)
    if (this.enableRecovery && this.running && !this.isShuttingDown) {
      this.attemptRecovery();
    }
  }

  /**
   * Attempt to recover connection with exponential backoff (O-H8)
   */
  private async attemptRecovery(): Promise<void> {
    if (this.recoveryAttempts >= this.maxRecoveryAttempts) {
      this.emit('recovery-failed', {
        attempts: this.recoveryAttempts,
        maxAttempts: this.maxRecoveryAttempts,
      });
      return;
    }

    this.recoveryAttempts++;
    this.metrics.recoveryAttempts++;

    // Exponential backoff: 1s, 2s, 4s, 8s, 16s
    const delay = Math.min(1000 * Math.pow(2, this.recoveryAttempts - 1), 16000);

    this.emit('recovery-attempt', {
      attempt: this.recoveryAttempts,
      maxAttempts: this.maxRecoveryAttempts,
      delay,
    });

    await new Promise((resolve) => setTimeout(resolve, delay));

    if (!this.running || this.isShuttingDown) {
      return;
    }

    try {
      // Clean up old process
      if (this.upstreamProcess) {
        this.upstreamProcess.kill();
        this.upstreamProcess = null;
      }
      this.upstreamTransport?.close();
      this.upstreamTransport = null;

      // Restart
      await this.start();

      this.emit('recovery-success', { attempts: this.recoveryAttempts });
    } catch (error) {
      this.emit('recovery-error', { error, attempt: this.recoveryAttempts });
      // Will be called again via handleUpstreamFailure if start fails
    }
  }

  private logAudit(entry: Partial<AuditEntry>): void {
    const fullEntry: AuditEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      tool: entry.tool || 'unknown',
      riskLevel: entry.riskLevel || 'write',
      decision: entry.decision || 'denied',
      ...entry,
    };

    this.options.onAuditEntry?.(fullEntry);
    this.emit('audit', fullEntry);
  }

  /**
   * Graceful shutdown with cleanup (O-H9)
   */
  async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    this.running = false;

    this.emit('shutdown-started');

    // Stop timeout checker (O-H6)
    if (this.timeoutCheckInterval) {
      clearInterval(this.timeoutCheckInterval);
      this.timeoutCheckInterval = null;
    }

    // Clear all pending request timeouts (O-H6)
    for (const [id, pending] of this.pendingRequests) {
      if (pending.timeoutHandle) {
        clearTimeout(pending.timeoutHandle);
      }

      // Send cancellation to client
      const response = createErrorResponse(
        id,
        JSONRPCErrorCodes.SERVER_SHUTTING_DOWN,
        'Server shutting down'
      );
      this.clientTransport.send(response);
    }
    this.pendingRequests.clear();

    // Close transports
    this.clientTransport.close();
    this.upstreamTransport?.close();

    // Gracefully terminate upstream process
    if (this.upstreamProcess) {
      // Give process time to terminate gracefully
      const killTimeout = setTimeout(() => {
        if (this.upstreamProcess) {
          this.upstreamProcess.kill('SIGKILL');
        }
      }, 5000);

      this.upstreamProcess.kill('SIGTERM');

      // Wait for process to exit
      await new Promise<void>((resolve) => {
        if (!this.upstreamProcess) {
          clearTimeout(killTimeout);
          resolve();
          return;
        }

        this.upstreamProcess.once('exit', () => {
          clearTimeout(killTimeout);
          resolve();
        });
      });

      this.upstreamProcess = null;
    }

    this.emit('shutdown');
  }

  getStats(): {
    serverName: string;
    sessionId: string;
    pendingRequests: number;
    running: boolean;
    circuitBreakerState: CircuitBreakerState;
    metrics: {
      requestsTotal: number;
      requestsTimedOut: number;
      requestsFailed: number;
      circuitBreakerTrips: number;
      recoveryAttempts: number;
    };
  } {
    return {
      serverName: this.options.serverName,
      sessionId: this.sessionId,
      pendingRequests: this.pendingRequests.size,
      running: this.running,
      circuitBreakerState: this.circuitBreaker.getState(),
      metrics: { ...this.metrics },
    };
  }

  /**
   * Get circuit breaker for external access
   */
  getCircuitBreaker(): CircuitBreaker {
    return this.circuitBreaker;
  }
}
