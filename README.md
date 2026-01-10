# Overwatch

[![Build](https://github.com/dotsetlabs/overwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/dotsetlabs/overwatch/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@dotsetlabs/overwatch)](https://www.npmjs.com/package/@dotsetlabs/overwatch)
[![License](https://img.shields.io/github/license/dotsetlabs/overwatch)](LICENSE)
[![Node Version](https://img.shields.io/node/v/@dotsetlabs/overwatch)](https://nodejs.org/)

**The AI Agent Firewall**

Runtime security proxy for MCP (Model Context Protocol). Overwatch protects AI development environments by detecting tool impersonation attacks and enforcing policy-based access control.

## The Threat: Tool Shadowing

MCP is the standard protocol for AI agent tool access. While basic RBAC controls *who* can access tools, it doesn't verify *what* the tool actually is. This creates a critical attack surface:

- **Tool Shadowing (CVE-2025-6514)**: Malicious MCP servers impersonate legitimate tools (e.g., a fake `postgres` tool that exfiltrates queries)
- **Schema Mutation**: Tools change behavior mid-session after initial trust is established
- **Name Collisions**: Multiple servers expose tools with identical names but different implementations

Traditional firewalls don't monitor MCP traffic. **Overwatch is the AI Agent Firewall.**

## Installation

```bash
npm install -g @dotsetlabs/overwatch
```

## Core Features

### 1. Tool Shadowing Detection (FLAGSHIP)

Cryptographic verification that tools are what they claim to be.

| Detection | Severity | Description |
|-----------|----------|-------------|
| Name Collision | Critical | Same tool name from multiple servers with different schemas |
| Schema Mutation | Critical | Tool definition changed mid-session |
| Suspicious Description | High | Tool description contains injection patterns |
| Hash Verification | High | Tool schema hash doesn't match baseline |

Tool Shadowing detection is **enabled by default** with no configuration required.

### 2. Policy-Based Access Control

Declarative policies for human-in-the-loop control without approval fatigue.

| Approval | Effect |
|----------|--------|
| `[y]` | Allow once |
| `[n]` | Deny |
| `[5]` | Allow for 5 minutes |
| `[s]` | Allow for session |

### 3. Audit Logging

Complete audit trail of all MCP tool calls with export support for SIEM integration.

## Usage

### MCP Security Proxy

```bash
# Wrap any MCP server with policy enforcement
overwatch wrap npx @modelcontextprotocol/server-postgres

# Wrap with strict policy
overwatch wrap --policy strict npx @modelcontextprotocol/server-filesystem
```

### Initialize & Diagnose

```bash
# Create overwatch.yaml config
overwatch init

# Check configuration
overwatch doctor
```

### Audit Logs

```bash
# View recent activity
overwatch logs

# Tail logs in real-time
overwatch logs --tail

# Export for SIEM
overwatch logs --format cef > audit.cef
```

## How Tool Shadowing Detection Works

```
               ┌─────────────────────────────┐
               │     Tool Shadowing          │
               │     Detector                │
               │ ┌─────────────────────────┐ │
AI Client ───▶│ │ • Hash tool schemas     │ │───▶ MCP Server
               │ │ • Detect collisions     │ │
               │ │ • Monitor mutations     │ │
               │ │ • Flag suspicious desc  │ │
               │ └─────────────────────────┘ │
               └─────────────────────────────┘
```

## Configuration

```yaml
# overwatch.yaml
servers:
  postgres:
    command: npx @modelcontextprotocol/server-postgres
    policies:
      - tools: ["query", "execute"]
        action: prompt

      - tools: ["*"]
        paths:
          deny: ["/etc/**", "~/.ssh/**"]

defaults:
  action: prompt

audit:
  enabled: true
  path: ~/.overwatch/audit.log
  format: json
```

## Claude Desktop Integration

```json
{
  "mcpServers": {
    "postgres": {
      "command": "overwatch",
      "args": ["wrap", "npx", "@modelcontextprotocol/server-postgres"]
    }
  }
}
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `overwatch wrap <cmd>` | Wrap an MCP server with security proxy |
| `overwatch start` | Start proxy with config file |
| `overwatch init` | Create default configuration |
| `overwatch doctor` | Diagnose configuration issues |
| `overwatch logs` | View audit logs |
| `overwatch stats` | View usage statistics |
| `overwatch sessions` | Manage active sessions |
| `overwatch policies` | View configured policies |

## Why Overwatch?

| What Overwatch Does | What Other Tools Do |
|---------------------|---------------------|
| Proxies MCP protocol traffic | Unaware of MCP |
| Detects tool shadowing attacks | No tool verification |
| Policy at protocol layer | Application-level only |
| Session-based approvals | All-or-nothing access |

## Performance

Overwatch adds minimal latency to MCP operations. All security checks happen in-process with no network calls.

| Operation | Time | Description |
|-----------|------|-------------|
| Tool Registration | 1.8ms | Register 100 tools with schema hashing |
| Collision Check | <1μs | Check for cross-server name collisions |
| Mutation Check | 3μs | Verify tool schema hasn't changed |
| Description Analysis | 15μs | Scan for suspicious patterns (40+ checks) |

**Overhead per tool call: <20μs** for full security analysis including collision detection, mutation monitoring, and description scanning.

### Memory Footprint

- Base proxy: ~15MB RSS
- Per registered tool: ~2KB (schema hash + metadata)
- Audit log buffer: Configurable, defaults to 1000 entries

## Part of Dotset Labs

Overwatch focuses on **runtime protection** of AI tool operations. For static analysis of AI config files, see [Hardpoint](https://github.com/dotsetlabs/hardpoint).

```
SCAN (Hardpoint)  →  CONTROL (Overwatch)
Defend against       Stop Tool Shadowing
Rules File Backdoor  and Rogue Agents
```

## License

MIT
