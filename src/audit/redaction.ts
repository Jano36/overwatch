// PII and credential redaction patterns

export interface RedactionResult {
  redacted: string;
  patternsMatched: string[];
}

// API Keys and tokens
const apiKeyPatterns = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET)[=:\s]["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36}/g },
  { name: 'GitHub PAT', pattern: /github_pat_[A-Za-z0-9]{22,}/g },
  { name: 'GitLab Token', pattern: /glpat-[A-Za-z0-9-]{20,}/g },
  { name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{48}/g },
  { name: 'OpenAI Project Key', pattern: /sk-proj-[A-Za-z0-9]{48}/g },
  { name: 'Anthropic Key', pattern: /sk-ant-[A-Za-z0-9\-]{95}/g },
  { name: 'Stripe Key', pattern: /[sr]k_(live|test)_[A-Za-z0-9]{23,}/g },
  { name: 'Slack Token', pattern: /xox[baprs]-[A-Za-z0-9\-]+/g },
  { name: 'Slack Webhook', pattern: /hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g },
  { name: 'npm Token', pattern: /npm_[A-Za-z0-9]{36}/g },
  { name: 'PyPI Token', pattern: /pypi-[A-Za-z0-9\-_]{100,}/g },
  { name: 'Heroku API Key', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g },
  { name: 'Google API Key', pattern: /AIza[A-Za-z0-9\-_]{35}/g },
  { name: 'Firebase Key', pattern: /AAAA[A-Za-z0-9\-_]{100,}/g },
  { name: 'SendGrid Key', pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g },
  { name: 'Twilio Key', pattern: /SK[a-z0-9]{32}/g },
  { name: 'Mailchimp Key', pattern: /[a-z0-9]{32}-us[0-9]{1,2}/g },
];

// Personal Identifiable Information
const piiPatterns = [
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
  { name: 'Phone (US)', pattern: /\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
  { name: 'SSN', pattern: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g },
  { name: 'Credit Card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
  { name: 'IP Address', pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g },
];

// Password and secret patterns in strings
const secretPatterns = [
  { name: 'Password Field', pattern: /(?:password|passwd|pwd)[=:\s]["']?[^"'\s]{8,}["']?/gi },
  { name: 'Secret Field', pattern: /(?:secret|token|api_key|apikey|auth)[=:\s]["']?[^"'\s]{8,}["']?/gi },
  { name: 'Private Key Header', pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9\-_.~+/]+=*/g },
  { name: 'Basic Auth', pattern: /Basic\s+[A-Za-z0-9+/]+=*/g },
  { name: 'Connection String Password', pattern: /(?:password|pwd)=[^;&\s]+/gi },
];

const REDACTED = '[REDACTED]';

export function redactPII(text: string): RedactionResult {
  let redacted = text;
  const patternsMatched: string[] = [];

  // Redact API keys
  for (const { name, pattern } of apiKeyPatterns) {
    const matches = redacted.match(pattern);
    if (matches && matches.length > 0) {
      patternsMatched.push(name);
      redacted = redacted.replace(pattern, REDACTED);
    }
  }

  // Redact PII
  for (const { name, pattern } of piiPatterns) {
    const matches = redacted.match(pattern);
    if (matches && matches.length > 0) {
      patternsMatched.push(name);
      redacted = redacted.replace(pattern, REDACTED);
    }
  }

  // Redact secrets
  for (const { name, pattern } of secretPatterns) {
    const matches = redacted.match(pattern);
    if (matches && matches.length > 0) {
      patternsMatched.push(name);
      redacted = redacted.replace(pattern, (match) => {
        // Keep the key name, redact the value
        const eqIndex = match.search(/[=:\s]/);
        if (eqIndex > 0) {
          return match.substring(0, eqIndex + 1) + REDACTED;
        }
        return REDACTED;
      });
    }
  }

  return { redacted, patternsMatched };
}

export function redactObject(obj: unknown): unknown {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    return redactPII(obj).redacted;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => redactObject(item));
  }

  if (typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      // Redact values for sensitive keys
      const sensitiveKeys = ['password', 'secret', 'token', 'key', 'auth', 'credential', 'api_key', 'apikey'];
      if (sensitiveKeys.some(k => key.toLowerCase().includes(k))) {
        result[key] = REDACTED;
      } else {
        result[key] = redactObject(value);
      }
    }
    return result;
  }

  return obj;
}

export function containsSensitiveData(text: string): boolean {
  const allPatterns = [...apiKeyPatterns, ...piiPatterns, ...secretPatterns];

  for (const { pattern } of allPatterns) {
    // Reset regex state
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      return true;
    }
  }

  return false;
}
