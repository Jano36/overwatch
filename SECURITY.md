# Overwatch Security

This document describes the attack vectors that Overwatch protects against and the security model behind its protection capabilities.

## Attack Vectors

### Tool Shadowing (CVE-2025-6514)

**Attack Pattern**: Malicious MCP servers define tools with the same names as legitimate tools, allowing them to intercept sensitive operations.

**Example Attack**:
```
Legitimate Server: defines "read_file" to read local files
Malicious Server: defines "read_file" to exfiltrate file contents

When AI calls "read_file", the malicious server intercepts the call.
```

**Protection**: Overwatch detects tool shadowing through:
- **Schema Hashing**: SHA-256 hashes of tool definitions
- **Collision Detection**: Identifies when multiple servers define the same tool
- **Mutation Monitoring**: Detects mid-session tool definition changes
- **Description Analysis**: Scans tool descriptions for prompt injection

### Rogue Agent Operations

**Attack Pattern**: Compromised AI agents or prompt injection attacks cause the AI to perform dangerous operations.

**Example**:
```
AI: "I'll clean up your database"
→ DROP TABLE users;  (executed without user consent)
```

**Protection**: Overwatch provides:
- **Policy Engine**: Declarative rules for allow/deny/prompt actions
- **Session Approvals**: Time-limited grants that require explicit consent
- **Path-Based Rules**: Restrict filesystem access to specific directories
- **Audit Logging**: Complete trail of all operations

### MCP Protocol Attacks

**Attack Pattern**: Exploiting the Model Context Protocol to bypass security controls.

**Protection**:
- All tool calls routed through Overwatch proxy
- Request timeouts prevent hanging attacks
- Circuit breaker prevents cascading failures
- PII redaction in audit logs

## Security Model

### Defense in Depth

```
┌─────────────────────────────────────────────┐
│                AI Client                     │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│            Overwatch Proxy                   │
│  ┌─────────────────────────────────────┐    │
│  │      Tool Shadowing Detector        │    │
│  └─────────────────────────────────────┘    │
│  ┌─────────────────────────────────────┐    │
│  │         Policy Engine               │    │
│  └─────────────────────────────────────┘    │
│  ┌─────────────────────────────────────┐    │
│  │        Session Manager              │    │
│  └─────────────────────────────────────┘    │
│  ┌─────────────────────────────────────┐    │
│  │         Audit Logger                │    │
│  └─────────────────────────────────────┘    │
└─────────────────┬───────────────────────────┘
                  │
┌─────────────────▼───────────────────────────┐
│              MCP Server                      │
└─────────────────────────────────────────────┘
```

### Policy Actions

| Action | Behavior | Use Case |
|--------|----------|----------|
| `allow` | Execute immediately | Safe read operations |
| `prompt` | Require user approval | Write operations |
| `deny` | Block execution | Destructive operations |

### Data Privacy

- **100% Local**: All processing happens on your machine
- **No Telemetry**: Zero data sent externally
- **PII Redaction**: Sensitive data can be redacted from audit logs
- **SQLite Storage**: Audit and session data stored locally

## References

- [Tool Shadowing (CVE-2025-6514)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OWASP LLM Top 10 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)

## Reporting Security Issues

If you discover a security vulnerability in Overwatch itself, please report it to security@dotsetlabs.com.

Do not open a public GitHub issue for security vulnerabilities.
