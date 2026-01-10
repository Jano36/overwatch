/**
 * Webhook-based approval handler for Overwatch
 *
 * Sends approval requests to an external webhook endpoint
 * and waits for a response. Supports HMAC-SHA256 signing
 * and automatic retry with exponential backoff.
 */

import type { ApprovalHandler, ApprovalRequest, ApprovalResponse } from './types.js';

/**
 * Configuration for the webhook approval handler.
 */
export interface WebhookApprovalConfig {
  /** The webhook URL to POST approval requests to */
  url: string;

  /** Timeout in milliseconds for the webhook request (default: 60000) */
  timeoutMs?: number;

  /** Optional headers to include with the request */
  headers?: Record<string, string>;

  /** Secret for HMAC-SHA256 signing webhook payloads */
  secret?: string;

  /** Number of retry attempts on failure (default: 3) */
  retryAttempts?: number;

  /** Initial delay between retries in ms (default: 1000) */
  retryDelayMs?: number;

  /** Maximum delay between retries in ms (default: 30000) */
  maxRetryDelayMs?: number;
}

/**
 * Expected response from the webhook endpoint.
 */
export interface WebhookPayload {
  /** Whether to approve (true) or deny (false) */
  approved: boolean;

  /** Optional session duration grant */
  sessionDuration?: 'once' | '5min' | '15min' | 'session';

  /** Optional reason for approval/denial */
  reason?: string;
}

const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 1000;
const DEFAULT_MAX_RETRY_DELAY_MS = 30000;

/**
 * Webhook approval handler that sends requests to an external endpoint.
 *
 * The webhook receives a POST request with the approval request details
 * and should respond with a JSON payload indicating approval/denial.
 *
 * @example
 * ```typescript
 * const handler = new WebhookApprovalHandler({
 *   url: 'https://example.com/api/overwatch/approve',
 *   timeoutMs: 30000,
 *   headers: { 'Authorization': 'Bearer token' },
 *   secret: 'my-webhook-secret',
 * });
 *
 * const response = await handler.requestApproval(request);
 * ```
 *
 * Expected webhook response format:
 * ```json
 * {
 *   "approved": true,
 *   "sessionDuration": "15min",
 *   "reason": "Auto-approved by policy"
 * }
 * ```
 */
export class WebhookApprovalHandler implements ApprovalHandler {
  private config: Required<
    Pick<WebhookApprovalConfig, 'url' | 'timeoutMs' | 'retryAttempts' | 'retryDelayMs' | 'maxRetryDelayMs'>
  > &
    Omit<WebhookApprovalConfig, 'url' | 'timeoutMs' | 'retryAttempts' | 'retryDelayMs' | 'maxRetryDelayMs'>;
  private abortController: AbortController | null = null;

  constructor(config: WebhookApprovalConfig) {
    this.config = {
      timeoutMs: DEFAULT_TIMEOUT_MS,
      retryAttempts: DEFAULT_RETRY_ATTEMPTS,
      retryDelayMs: DEFAULT_RETRY_DELAY_MS,
      maxRetryDelayMs: DEFAULT_MAX_RETRY_DELAY_MS,
      ...config,
    };
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    try {
      const result = await this.sendWebhookRequest(request);
      return {
        approved: result.approved,
        sessionDuration: result.sessionDuration,
        reason: result.reason,
      };
    } catch (error) {
      // On error, deny by default
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        approved: false,
        reason: `Webhook error: ${errorMessage}`,
      };
    }
  }

  /**
   * Sends the approval request to the webhook endpoint with retry logic.
   */
  private async sendWebhookRequest(request: ApprovalRequest): Promise<WebhookPayload> {
    const { retryAttempts, retryDelayMs, maxRetryDelayMs } = this.config;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retryAttempts; attempt++) {
      try {
        return await this.doWebhookRequest(request);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on abort (timeout/cancellation)
        if (lastError.name === 'AbortError') {
          throw lastError;
        }

        // Don't retry on final attempt
        if (attempt === retryAttempts) {
          throw lastError;
        }

        // Calculate delay with exponential backoff
        const delay = Math.min(retryDelayMs * Math.pow(2, attempt), maxRetryDelayMs);
        await this.sleep(delay);
      }
    }

    throw lastError ?? new Error('Webhook request failed');
  }

  /**
   * Performs a single webhook request attempt.
   */
  private async doWebhookRequest(request: ApprovalRequest): Promise<WebhookPayload> {
    this.abortController = new AbortController();
    const timeout = this.config.timeoutMs;

    // Set up timeout
    const timeoutId = setTimeout(() => {
      this.abortController?.abort();
    }, timeout);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...this.config.headers,
      };

      // Build request body
      const body = JSON.stringify({
        id: request.id,
        timestamp: request.timestamp.toISOString(),
        server: request.server,
        tool: request.tool,
        args: request.args,
        riskLevel: request.riskLevel,
        reason: request.reason,
      });

      // Add HMAC signature if secret is configured
      if (this.config.secret) {
        const signature = await this.computeSignature(body);
        headers['X-Overwatch-Signature'] = signature;
      }

      const response = await fetch(this.config.url, {
        method: 'POST',
        headers,
        body,
        signal: this.abortController.signal,
      });

      if (!response.ok) {
        throw new Error(`Webhook returned status ${response.status}: ${response.statusText}`);
      }

      const payload = (await response.json()) as WebhookPayload;

      // Validate response
      if (typeof payload.approved !== 'boolean') {
        throw new Error('Invalid webhook response: missing "approved" field');
      }

      return payload;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Sleep helper for retry delays.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Computes HMAC-SHA256 signature for the payload.
   */
  private async computeSignature(body: string): Promise<string> {
    if (!this.config.secret) {
      return '';
    }

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(this.config.secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
    const hashArray = Array.from(new Uint8Array(signature));
    return 'sha256=' + hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async close(): Promise<void> {
    this.abortController?.abort();
    this.abortController = null;
  }
}

// =============================================================================
// Webhook Signature Verification Helper
// =============================================================================

/**
 * Verify a webhook signature from Overwatch.
 *
 * Use this function in your webhook receiver to validate that requests
 * are authentic and haven't been tampered with.
 *
 * @example
 * ```typescript
 * import { verifyWebhookSignature } from '@dotsetlabs/overwatch';
 *
 * app.post('/webhook/overwatch', async (req, res) => {
 *   const signature = req.headers['x-overwatch-signature'];
 *   const body = JSON.stringify(req.body);
 *
 *   const isValid = await verifyWebhookSignature(body, signature, process.env.WEBHOOK_SECRET);
 *
 *   if (!isValid) {
 *     return res.status(401).json({ error: 'Invalid signature' });
 *   }
 *
 *   // Process the webhook...
 * });
 * ```
 *
 * @param body - The raw request body as a string
 * @param signature - The X-Overwatch-Signature header value
 * @param secret - Your webhook secret
 * @returns Promise<boolean> - True if signature is valid
 */
export async function verifyWebhookSignature(
  body: string,
  signature: string | null | undefined,
  secret: string
): Promise<boolean> {
  if (!signature || !secret) {
    return false;
  }

  // Remove 'sha256=' prefix if present
  const providedSig = signature.startsWith('sha256=') ? signature.slice(7) : signature;

  try {
    // Compute expected signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const computed = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
    const expectedSig = Array.from(new Uint8Array(computed))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // Timing-safe comparison to prevent timing attacks
    if (providedSig.length !== expectedSig.length) {
      return false;
    }

    let mismatch = 0;
    for (let i = 0; i < providedSig.length; i++) {
      mismatch |= providedSig.charCodeAt(i) ^ expectedSig.charCodeAt(i);
    }

    return mismatch === 0;
  } catch {
    return false;
  }
}

/**
 * Result type for webhook signature verification.
 */
export interface WebhookVerificationResult {
  /** Whether the signature is valid */
  valid: boolean;

  /** Reason for invalid signature */
  reason?: string;
}

/**
 * Verify a webhook signature with detailed result.
 *
 * @param body - The raw request body as a string
 * @param signature - The X-Overwatch-Signature header value
 * @param secret - Your webhook secret
 * @returns Promise<WebhookVerificationResult>
 */
export async function verifyWebhookSignatureDetailed(
  body: string,
  signature: string | null | undefined,
  secret: string
): Promise<WebhookVerificationResult> {
  if (!signature) {
    return { valid: false, reason: 'Missing signature header' };
  }

  if (!secret) {
    return { valid: false, reason: 'Missing webhook secret' };
  }

  if (!signature.startsWith('sha256=')) {
    return { valid: false, reason: 'Invalid signature format (expected sha256=...)' };
  }

  const isValid = await verifyWebhookSignature(body, signature, secret);

  if (isValid) {
    return { valid: true };
  }

  return { valid: false, reason: 'Signature mismatch' };
}

/**
 * Factory function to create a webhook approval handler.
 */
export function createWebhookApprovalHandler(config: WebhookApprovalConfig): WebhookApprovalHandler {
  return new WebhookApprovalHandler(config);
}
