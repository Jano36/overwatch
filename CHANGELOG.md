# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-01-10

### Added

- Initial release
- MCP Security Proxy with tool call interception
- Policy Engine with allow/deny/prompt actions
- Tool Shadowing Detection (CVE-2025-6514)
  - Schema hashing (SHA-256)
  - Collision detection across MCP servers
  - Mutation monitoring for mid-session changes
  - Description analysis for prompt injection
- Session-based approvals with SQLite persistence
- Path-based access rules for filesystem operations
- Audit logging with JSON, CSV, CEF export formats
- `wrap` command for wrapping MCP servers
- `start` command for multi-server mode
- `sessions` command for managing approvals
- `logs` command for viewing audit trail
- `stats` command for usage statistics
- `init` command for configuration setup
- `policies` command for policy management
- `doctor` command for installation diagnostics
- PII redaction support in audit logs

[Unreleased]: https://github.com/dotsetlabs/overwatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dotsetlabs/overwatch/releases/tag/v0.1.0
