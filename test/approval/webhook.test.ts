import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  WebhookApprovalHandler,
  createWebhookApprovalHandler,
  verifyWebhookSignature,
  verifyWebhookSignatureDetailed,
} from '../../src/approval/webhook.js';
import type { ApprovalRequest } from '../../src/approval/types.js';

describe('WebhookApprovalHandler', () => {
  let handler: WebhookApprovalHandler;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  function createRequest(overrides: Partial<ApprovalRequest> = {}): ApprovalRequest {
    return {
      id: 'test-request-1',
      tool: 'read_file',
      riskLevel: 'read',
      timestamp: new Date('2024-01-01T00:00:00Z'),
      ...overrides,
    };
  }

  describe('basic functionality', () => {
    it('sends POST request to webhook URL', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ approved: true }),
      });

      const request = createRequest();
      await handler.requestApproval(request);

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        'https://example.com/webhook',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      );
    });

    it('returns approved response when webhook approves', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          approved: true,
          sessionDuration: '15min',
          reason: 'Auto-approved',
        }),
      });

      const response = await handler.requestApproval(createRequest());

      expect(response.approved).toBe(true);
      expect(response.sessionDuration).toBe('15min');
      expect(response.reason).toBe('Auto-approved');
    });

    it('returns denied response when webhook denies', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          approved: false,
          reason: 'Policy violation',
        }),
      });

      const response = await handler.requestApproval(createRequest());

      expect(response.approved).toBe(false);
      expect(response.reason).toBe('Policy violation');
    });

    it('sends custom headers when configured', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        headers: {
          Authorization: 'Bearer test-token',
          'X-Custom-Header': 'custom-value',
        },
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ approved: true }),
      });

      await handler.requestApproval(createRequest());

      expect(fetchMock).toHaveBeenCalledWith(
        'https://example.com/webhook',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer test-token',
            'X-Custom-Header': 'custom-value',
          }),
        })
      );
    });

    it('includes request data in webhook payload', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ approved: true }),
      });

      const request = createRequest({
        id: 'unique-id',
        server: 'postgres',
        tool: 'query',
        args: { sql: 'SELECT * FROM users' },
        riskLevel: 'read',
        reason: 'Database query',
      });

      await handler.requestApproval(request);

      const [, options] = fetchMock.mock.calls[0];
      const body = JSON.parse(options.body);

      expect(body.id).toBe('unique-id');
      expect(body.server).toBe('postgres');
      expect(body.tool).toBe('query');
      expect(body.args).toEqual({ sql: 'SELECT * FROM users' });
      expect(body.riskLevel).toBe('read');
      expect(body.reason).toBe('Database query');
    });
  });

  describe('error handling', () => {
    it('returns denied on HTTP error', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      });

      const response = await handler.requestApproval(createRequest());

      expect(response.approved).toBe(false);
      expect(response.reason).toContain('Webhook error');
    });

    it('returns denied on invalid response', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ invalid: 'response' }),
      });

      const response = await handler.requestApproval(createRequest());

      expect(response.approved).toBe(false);
      expect(response.reason).toContain('missing "approved" field');
    });

    it('returns denied on network error', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockRejectedValueOnce(new Error('Network error'));

      const response = await handler.requestApproval(createRequest());

      expect(response.approved).toBe(false);
      expect(response.reason).toContain('Network error');
    });
  });

  describe('retry logic', () => {
    it('retries on failure', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 2,
        retryDelayMs: 10,
      });

      fetchMock
        .mockRejectedValueOnce(new Error('First failure'))
        .mockRejectedValueOnce(new Error('Second failure'))
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ approved: true }),
        });

      const response = await handler.requestApproval(createRequest());

      expect(fetchMock).toHaveBeenCalledTimes(3);
      expect(response.approved).toBe(true);
    });

    it('gives up after max retries', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 2,
        retryDelayMs: 10,
      });

      fetchMock.mockRejectedValue(new Error('Persistent failure'));

      const response = await handler.requestApproval(createRequest());

      expect(fetchMock).toHaveBeenCalledTimes(3); // Initial + 2 retries
      expect(response.approved).toBe(false);
      expect(response.reason).toContain('Persistent failure');
    });

    it('does not retry on abort', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 3,
        retryDelayMs: 10,
        timeoutMs: 50,
      });

      const abortError = new Error('Aborted');
      abortError.name = 'AbortError';
      fetchMock.mockRejectedValueOnce(abortError);

      const response = await handler.requestApproval(createRequest());

      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(response.approved).toBe(false);
    });
  });

  describe('HMAC signing', () => {
    it('adds signature header when secret is configured', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        secret: 'test-secret',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ approved: true }),
      });

      await handler.requestApproval(createRequest());

      const [, options] = fetchMock.mock.calls[0];
      expect(options.headers['X-Overwatch-Signature']).toBeDefined();
      expect(options.headers['X-Overwatch-Signature']).toMatch(/^sha256=[a-f0-9]+$/);
    });

    it('does not add signature header when no secret', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
        retryAttempts: 0,
      });

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ approved: true }),
      });

      await handler.requestApproval(createRequest());

      const [, options] = fetchMock.mock.calls[0];
      expect(options.headers['X-Overwatch-Signature']).toBeUndefined();
    });
  });

  describe('close', () => {
    it('can be closed without error', async () => {
      handler = new WebhookApprovalHandler({
        url: 'https://example.com/webhook',
      });

      await expect(handler.close()).resolves.not.toThrow();
    });
  });

  describe('createWebhookApprovalHandler', () => {
    it('creates a new handler instance', () => {
      const newHandler = createWebhookApprovalHandler({
        url: 'https://example.com/webhook',
      });

      expect(newHandler).toBeInstanceOf(WebhookApprovalHandler);
    });
  });
});

describe('Webhook Signature Verification', () => {
  describe('verifyWebhookSignature', () => {
    it('returns true for valid signature', async () => {
      const body = '{"approved": true}';
      const secret = 'test-secret';

      // First, generate a valid signature using the same logic
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
      const validSig =
        'sha256=' +
        Array.from(new Uint8Array(signature))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      const result = await verifyWebhookSignature(body, validSig, secret);
      expect(result).toBe(true);
    });

    it('returns false for invalid signature', async () => {
      const body = '{"approved": true}';
      const secret = 'test-secret';
      const invalidSig = 'sha256=invalid';

      const result = await verifyWebhookSignature(body, invalidSig, secret);
      expect(result).toBe(false);
    });

    it('returns false for missing signature', async () => {
      const body = '{"approved": true}';
      const secret = 'test-secret';

      const result = await verifyWebhookSignature(body, null, secret);
      expect(result).toBe(false);
    });

    it('returns false for missing secret', async () => {
      const body = '{"approved": true}';
      const signature = 'sha256=abc';

      const result = await verifyWebhookSignature(body, signature, '');
      expect(result).toBe(false);
    });

    it('handles signature without sha256= prefix', async () => {
      const body = '{"approved": true}';
      const secret = 'test-secret';

      // Generate valid signature without prefix
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
      const sigWithoutPrefix = Array.from(new Uint8Array(signature))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const result = await verifyWebhookSignature(body, sigWithoutPrefix, secret);
      expect(result).toBe(true);
    });
  });

  describe('verifyWebhookSignatureDetailed', () => {
    it('returns valid for correct signature', async () => {
      const body = '{"approved": true}';
      const secret = 'test-secret';

      // Generate valid signature
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(body));
      const validSig =
        'sha256=' +
        Array.from(new Uint8Array(signature))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      const result = await verifyWebhookSignatureDetailed(body, validSig, secret);
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('returns reason for missing signature', async () => {
      const result = await verifyWebhookSignatureDetailed('body', null, 'secret');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Missing signature header');
    });

    it('returns reason for missing secret', async () => {
      const result = await verifyWebhookSignatureDetailed('body', 'sha256=abc', '');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Missing webhook secret');
    });

    it('returns reason for invalid format', async () => {
      const result = await verifyWebhookSignatureDetailed('body', 'invalid', 'secret');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Invalid signature format (expected sha256=...)');
    });

    it('returns reason for signature mismatch', async () => {
      const result = await verifyWebhookSignatureDetailed('body', 'sha256=invalid', 'secret');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Signature mismatch');
    });
  });
});
