import { describe, it, expect } from 'vitest';
import {
  redactPII,
  redactObject,
  containsSensitiveData,
} from '../../src/audit/redaction.js';

describe('redactPII', () => {
  describe('API keys', () => {
    it('redacts AWS access keys', () => {
      const text = 'AWS key: AKIAIOSFODNN7EXAMPLE';
      const result = redactPII(text);
      expect(result.redacted).toBe('AWS key: [REDACTED]');
      expect(result.patternsMatched).toContain('AWS Access Key');
    });

    it('redacts AWS secret keys', () => {
      const text = 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
      const result = redactPII(text);
      expect(result.redacted).toContain('[REDACTED]');
      expect(result.patternsMatched).toContain('AWS Secret Key');
    });

    it('redacts GitHub tokens', () => {
      const text = 'Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Token: [REDACTED]');
      expect(result.patternsMatched).toContain('GitHub Token');
    });

    it('redacts GitHub PATs', () => {
      const text = 'PAT: github_pat_xxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('PAT: [REDACTED]');
      expect(result.patternsMatched).toContain('GitHub PAT');
    });

    it('redacts GitLab tokens', () => {
      const text = 'Token: glpat-xxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Token: [REDACTED]');
      expect(result.patternsMatched).toContain('GitLab Token');
    });

    it('redacts OpenAI keys', () => {
      const text = 'Key: sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Key: [REDACTED]');
      expect(result.patternsMatched).toContain('OpenAI Key');
    });

    it('redacts Anthropic keys', () => {
      const key = 'sk-ant-' + 'x'.repeat(95);
      const text = `Key: ${key}`;
      const result = redactPII(text);
      expect(result.redacted).toBe('Key: [REDACTED]');
      expect(result.patternsMatched).toContain('Anthropic Key');
    });

    it('redacts Stripe keys', () => {
      const text = 'Stripe: sk_test_TESTKEY1234567890abcdef';
      const result = redactPII(text);
      expect(result.redacted).toBe('Stripe: [REDACTED]');
      expect(result.patternsMatched).toContain('Stripe Key');
    });

    it('redacts Slack tokens', () => {
      const text = 'Token: xoxb-xxxxx-xxxxx-xxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Token: [REDACTED]');
      expect(result.patternsMatched).toContain('Slack Token');
    });

    it('redacts Slack webhooks', () => {
      const text = 'Webhook: hooks.slack.com/services/T00/B00/XXXX';
      const result = redactPII(text);
      expect(result.redacted).toBe('Webhook: [REDACTED]');
      expect(result.patternsMatched).toContain('Slack Webhook');
    });

    it('redacts npm tokens', () => {
      const text = 'Token: npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Token: [REDACTED]');
      expect(result.patternsMatched).toContain('npm Token');
    });

    it('redacts Google API keys', () => {
      // AIza + 35 chars = 39 total (AIza + SyB + 32 x's)
      const text = 'Key: AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const result = redactPII(text);
      expect(result.redacted).toBe('Key: [REDACTED]');
      expect(result.patternsMatched).toContain('Google API Key');
    });

    it('redacts SendGrid keys', () => {
      const key = 'SG.' + 'x'.repeat(22) + '.' + 'x'.repeat(43);
      const text = `Key: ${key}`;
      const result = redactPII(text);
      expect(result.redacted).toBe('Key: [REDACTED]');
      expect(result.patternsMatched).toContain('SendGrid Key');
    });

    it('redacts Twilio keys', () => {
      const text = 'Key: SK' + 'x'.repeat(32);
      const result = redactPII(text);
      expect(result.redacted).toBe('Key: [REDACTED]');
      expect(result.patternsMatched).toContain('Twilio Key');
    });
  });

  describe('PII', () => {
    it('redacts email addresses', () => {
      const text = 'Contact: john.doe@example.com for more info';
      const result = redactPII(text);
      expect(result.redacted).toBe('Contact: [REDACTED] for more info');
      expect(result.patternsMatched).toContain('Email');
    });

    it('redacts US phone numbers', () => {
      const formats = [
        '555-123-4567',
        '(555) 123-4567',
        '+1 555 123 4567',
        '555.123.4567',
      ];

      for (const phone of formats) {
        const result = redactPII(`Call me at ${phone}`);
        expect(result.redacted).toContain('[REDACTED]');
        expect(result.patternsMatched).toContain('Phone (US)');
      }
    });

    it('redacts SSNs', () => {
      const formats = [
        '123-45-6789',
        '123 45 6789',
        '123456789',
      ];

      for (const ssn of formats) {
        const result = redactPII(`SSN: ${ssn}`);
        expect(result.redacted).toContain('[REDACTED]');
        expect(result.patternsMatched).toContain('SSN');
      }
    });

    it('redacts credit card numbers', () => {
      const cards = [
        '4111111111111111', // Visa
        '5500000000000004', // Mastercard
        '340000000000009',  // Amex
        '6011000000000004', // Discover
      ];

      for (const card of cards) {
        const result = redactPII(`Card: ${card}`);
        expect(result.redacted).toContain('[REDACTED]');
        expect(result.patternsMatched).toContain('Credit Card');
      }
    });

    it('redacts IP addresses', () => {
      const text = 'Server at 192.168.1.100 and 10.0.0.1';
      const result = redactPII(text);
      expect(result.redacted).toBe('Server at [REDACTED] and [REDACTED]');
      expect(result.patternsMatched).toContain('IP Address');
    });
  });

  describe('secrets', () => {
    it('redacts password fields', () => {
      const text = 'password=supersecret123';
      const result = redactPII(text);
      expect(result.redacted).toBe('password=[REDACTED]');
      expect(result.patternsMatched).toContain('Password Field');
    });

    it('redacts secret fields', () => {
      const text = 'secret=mysecretvalue123';
      const result = redactPII(text);
      expect(result.redacted).toBe('secret=[REDACTED]');
      expect(result.patternsMatched).toContain('Secret Field');
    });

    it('redacts private key headers', () => {
      const text = '-----BEGIN RSA PRIVATE KEY-----';
      const result = redactPII(text);
      // The redaction preserves the prefix up to the first whitespace
      expect(result.redacted).toBe('-----BEGIN [REDACTED]');
      expect(result.patternsMatched).toContain('Private Key Header');
    });

    it('redacts bearer tokens', () => {
      const text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx';
      const result = redactPII(text);
      expect(result.redacted).toContain('[REDACTED]');
      expect(result.patternsMatched).toContain('Bearer Token');
    });

    it('redacts basic auth', () => {
      const text = 'Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=';
      const result = redactPII(text);
      expect(result.redacted).toContain('[REDACTED]');
      expect(result.patternsMatched).toContain('Basic Auth');
    });

    it('redacts connection string passwords', () => {
      const text = 'postgres://user:password=secret@localhost:5432/db';
      const result = redactPII(text);
      expect(result.redacted).toContain('password=[REDACTED]');
      expect(result.patternsMatched).toContain('Connection String Password');
    });
  });

  describe('no redaction needed', () => {
    it('returns original text when no sensitive data', () => {
      const text = 'This is a normal log message with no secrets';
      const result = redactPII(text);
      expect(result.redacted).toBe(text);
      expect(result.patternsMatched.length).toBe(0);
    });
  });
});

describe('redactObject', () => {
  it('redacts strings in objects', () => {
    const obj = {
      message: 'Contact john@example.com for help',
    };
    const result = redactObject(obj) as typeof obj;
    expect(result.message).toBe('Contact [REDACTED] for help');
  });

  it('redacts nested objects', () => {
    const obj = {
      user: {
        email: 'user@example.com',
        name: 'John Doe',
      },
    };
    const result = redactObject(obj) as typeof obj;
    expect(result.user.email).toBe('[REDACTED]');
  });

  it('redacts arrays', () => {
    const arr = ['normal', 'user@example.com', 'also normal'];
    const result = redactObject(arr) as string[];
    expect(result[0]).toBe('normal');
    expect(result[1]).toBe('[REDACTED]');
    expect(result[2]).toBe('also normal');
  });

  it('redacts sensitive key values entirely', () => {
    const obj = {
      username: 'john',
      password: 'supersecret',
      apiKey: 'key-123',
      auth_token: 'tok-456',
    };
    const result = redactObject(obj) as typeof obj;
    expect(result.username).toBe('john');
    expect(result.password).toBe('[REDACTED]');
    expect(result.apiKey).toBe('[REDACTED]');
    expect(result.auth_token).toBe('[REDACTED]');
  });

  it('handles null and undefined', () => {
    expect(redactObject(null)).toBeNull();
    expect(redactObject(undefined)).toBeUndefined();
  });

  it('passes through primitives', () => {
    expect(redactObject(42)).toBe(42);
    expect(redactObject(true)).toBe(true);
  });
});

describe('containsSensitiveData', () => {
  it('returns true when sensitive data is present', () => {
    expect(containsSensitiveData('Email: user@example.com')).toBe(true);
    expect(containsSensitiveData('Key: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')).toBe(true);
    expect(containsSensitiveData('password=secret123')).toBe(true);
  });

  it('returns false when no sensitive data', () => {
    expect(containsSensitiveData('Normal log message')).toBe(false);
    expect(containsSensitiveData('User performed action X')).toBe(false);
  });
});
