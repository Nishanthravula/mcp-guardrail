# Changelog

## 0.2.0

Making it easy to adopt without writing code.

### Added
- **Config file** (`--config <file>` or `MCP_GUARDRAIL_CONFIG`), with strict validation and "did you mean" suggestions for typos, plus a JSON schema (`guardrail.schema.json`) for editor autocomplete.
- **Allowlist**: `allow` (exact values) and `allowPatterns` (regexes that must match the whole value), also honored for values under sensitive keys.
- **Custom rules** from the config: regex, optional capture group, flags, and an entropy gate. Each is stress-tested at startup in a worker thread; patterns prone to runaway backtracking are rejected instead of stalling the proxy.
- **Per-tool policies**: `tools.<name>.skip` forwards a tool's results untouched; `tools.<name>.disable` turns rules off for one tool only.
- **`--dry-run`**: forward everything unchanged and report what would have been redacted or blocked.
- **`--audit-log <file>`**: JSONL audit trail with rule, tool, JSON path and a per-run HMAC fingerprint for each redaction. Never contains values; created owner-only.
- **`mcp-guardrail scan <path...|->`**: report what would be redacted in files, folders or stdin, with line and column, never printing values. `--json` output; exits 1 on findings.
- **`mcp-guardrail check-config <file>`**, `--help` and `--version`.
- Library: `Sanitizer#findings()`, per-redaction `details` (JSON path + optional `fingerprint`), and exported `loadConfig`, `validateConfig`, `compileRules`, `scanText`, `scanPaths`, `VERSION`.
- Release workflow publishing to npm through trusted publishing with provenance.

### Changed
- Messages that need no redaction are now forwarded byte-for-byte instead of being re-serialized.
- `--disable` now rejects unknown rule ids instead of ignoring them.

## 0.1.0

First release: stdio sanitizing proxy, built-in secret and PII detectors, request guard against writing placeholders back to disk, linear-time rules, end-to-end tests against the official filesystem MCP server.
