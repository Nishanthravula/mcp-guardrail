# mcp-guardrail

**Zero-dependency sanitizing proxy for MCP servers.** Redacts secrets and PII from Model Context Protocol payloads *before* they reach the LLM.

When you plug a filesystem, database, or API into Claude Code, Cursor, or any MCP host, every tool result flows straight into the model's context — including any AWS keys, connection-string passwords, JWTs, or customer emails that happen to be in your files. `mcp-guardrail` sits between the host and your MCP server and scrubs that traffic in real time.

```
LLM host (Claude Code / Cursor / ...) ⇄ mcp-guardrail ⇄ your MCP server
                                          │
                                          └─ redacts: AWS keys, API tokens, JWTs,
                                             private keys, DB passwords, emails,
                                             SSNs, credit cards, IPs …
```

## Quick start

```bash
npm install -g @nishanthravula/mcp-guardrail   # or run it with npx, as below
```

Wrap any stdio MCP server by prefixing its command:

```jsonc
// Claude Desktop / Claude Code MCP config
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "@nishanthravula/mcp-guardrail", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"
      ]
    }
  }
}
```

That's it. Tool results now arrive redacted:

```
Before:  DATABASE_URL=postgres://admin:pr0d-s3cret@db.internal:5432/app
After:   DATABASE_URL=postgres://[REDACTED:CONNECTION_STRING_CREDENTIALS]@db.internal:5432/app
```

Redaction summaries are logged to stderr (never the values themselves):

```
[mcp-guardrail] response: redacted AWS_ACCESS_KEY_ID×1, EMAIL×3
```

## Try it before you trust it

**See what it would catch in your files**, without wiring anything up:

```console
$ npx -y @nishanthravula/mcp-guardrail scan ./my-project
my-project/.env:2:19  AWS_ACCESS_KEY_ID  aws-access-key-id
    AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_ID]
my-project/config/database.yml:5:14  SECRET  generic-assigned-secret
    password: "[SECRET]"

2 finding(s) in 2 file(s); 41 file(s) scanned.
```

`scan` never prints a value, skips `node_modules`, `.git` and binary files, takes `-` for stdin, supports `--json`, and exits 1 when it finds something, so it also works as a pre-commit or CI check.

**Watch live traffic without changing it** with `--dry-run`: everything is forwarded untouched, and stderr (plus the audit log, if enabled) reports what *would* have been redacted or blocked.

## CLI

```
mcp-guardrail [options] -- <server command...>   wrap a stdio MCP server
mcp-guardrail scan [options] <path...|->         show what would be redacted
mcp-guardrail check-config <file>                validate a config file

  --config <file>       JSON config (also: MCP_GUARDRAIL_CONFIG env var)
  --both                also block requests that would send a secret TO the server
  --allow-placeholders  let requests containing "[REDACTED:...]" through (not recommended)
  --max-string N        truncate any string value longer than N characters (after redaction)
  --disable id1,id2     turn off rules (e.g. --disable email,ipv4,phone)
  --dry-run             report what would be redacted or blocked; change nothing
  --audit-log <file>    append a JSONL audit log (never contains values)
  --quiet               no stderr logs
  --json, --no-color    scan output format
```

Flags override the config file; `--disable` adds to the config's list.

## Configuration file

For anything beyond a few flags, use a JSON config. Add `$schema` for autocomplete and inline docs in VS Code and other editors:

```jsonc
{
  "$schema": "https://unpkg.com/@nishanthravula/mcp-guardrail/guardrail.schema.json",

  // Values that are never redacted (exact match), and patterns that must match the whole value
  "allow": ["support@acme.io", "4111 1111 1111 1111"],
  "allowPatterns": ["10\\.0\\.\\d{1,3}\\.\\d{1,3}"],

  // Your own detectors, applied after the built-ins
  "rules": [
    { "id": "acme-api-key", "label": "ACME_API_KEY", "pattern": "acme_[A-Za-z0-9]{32}" },
    { "id": "employee-id", "category": "pii", "pattern": "\\bEMP-\\d{6}\\b" },
    { "id": "pin", "pattern": "PIN[=:](\\d{6})", "group": 1, "flags": "i" }
  ],

  // Per-tool policies, keyed by MCP tool name
  "tools": {
    "read_media_file": { "skip": true },              // images only: forward untouched
    "list_directory": { "disable": ["email"] }        // folder names stay usable
  },

  "auditLog": "./guardrail-audit.jsonl"               // relative to this file
}
```

The file itself is plain JSON (comments above are for illustration). Use it with `--config guardrail.json`, and check it with `mcp-guardrail check-config guardrail.json`.

Validation is strict: an unknown key or rule id stops startup with a suggestion (`unknown key "dissable" (did you mean "disable"?)`), because in a security tool a typo shouldn't silently do nothing. Custom regexes are also stress-tested at startup on adversarial input; a pattern that could backtrack catastrophically (like `(a+)+$`) is rejected rather than allowed to stall every message.

## Audit log

`--audit-log <file>` (or `"auditLog"`) appends one JSON line per event: `start`, `redact` / `would-redact`, `block` / `would-block`, `stop`. Each redaction records the rule, the MCP tool, and the JSON path it was found at, plus a short fingerprint so you can tell one key appearing 40 times from 40 different keys:

```json
{"ts":"2026-11-11T08:12:03.114Z","event":"redact","tool":"read_text_file","id":4,
 "redactions":{"AWS_ACCESS_KEY_ID":2},
 "details":[{"rule":"aws-access-key-id","path":"result.content[0].text","fp":"9c41e07a2b5d13f8"}, …]}
```

The log never contains values. Fingerprints are HMACs with a random key generated per run, so they only correlate within one session and can't be used to brute-force short passwords. The file is created owner-only (`0600`), since it does reveal which files and tools carried secrets.

## Writes are protected too

A model only ever sees the redacted version of your files. If it writes one back whole, the real secrets on disk would be replaced by `[REDACTED:...]` placeholders. So `mcp-guardrail` checks every request going to the server. If a request contains a redaction placeholder, it is **blocked** and the model gets a clear error explaining why. Targeted edits that don't touch a redacted value go through normally.

With `--both`, requests that contain a *secret* (not PII such as paths or names) are blocked as well, so a model can't send credentials to the server. Requests are never rewritten: silently changing what gets written would corrupt your data.

## What it detects

| Category | Rules |
|---|---|
| Cloud & vendor keys | AWS access key IDs & secret keys, Anthropic, OpenAI, Google, Stripe, Slack, GitHub tokens/PATs |
| Crypto material | JWTs, PEM / OpenSSH / PGP private key blocks |
| Credentials | `user:password@` and `token@` in URLs, `Bearer` / `Basic` auth headers, entropy-gated `NAME=value` secrets (`DB_PASSWORD=`, `JWT_SECRET:`, `"apiKey": "..."`) |
| Structured data | Any string under a sensitive key (`password`, `api_key`, `accessToken`, `client_secret`, `Authorization`, …) in tool results and `structuredContent` |
| PII | Emails, SSNs, credit cards (Luhn + card-network prefix), US and international phone numbers, IPv4/IPv6 addresses (except loopback and RFC documentation ranges) |

False-positive controls: cards must pass Luhn *and* carry a real network prefix and length; `NAME=value` secrets must clear a length-scaled entropy bar and are skipped when the value is code (`options.clientSecret`), a reference (`${DB_PASSWORD}`, `<your-token>`), a path or a URL; IPs are parsed with `node:net`, so versions, MAC addresses, times and `Foo::Bar` are left alone; pagination and progress tokens are never touched; overlapping matches resolve to the most specific rule via single-pass range redaction (placeholders can never be re-matched). JSON-RPC `id`, `method` and `jsonrpc` are never altered.

Every rule is tested for linear-time behavior on adversarial input (`tests/redos.test.ts`), so content a server returns can't freeze the proxy.

## Library usage

```ts
import { Sanitizer } from "@nishanthravula/mcp-guardrail";

const sanitizer = new Sanitizer({
  maxStringLength: 20_000,
  disable: ["ipv4"],
  extraRules: [{
    id: "internal-ticket",
    label: "TICKET_ID",
    category: "pii",
    pattern: /\bACME-\d{6}\b/g,
  }],
});

const { value, redactions } = sanitizer.sanitize(toolResult);
```

Or embed the proxy programmatically:

```ts
import { GuardrailProxy } from "@nishanthravula/mcp-guardrail";

new GuardrailProxy({
  command: "npx",
  args: ["-y", "@modelcontextprotocol/server-postgres", process.env.DB_URL],
  maxStringLength: 50_000,
}).start();
```

## Why not X?

- **gitleaks / detect-secrets** — excellent rulesets, but built for scanning repos at rest, not intercepting a live JSON-RPC stream.
- **llm-guard** — a full Python guard framework; heavier, and not an MCP transport wrapper.
- **MCP gateways** — powerful, but require running infrastructure. `mcp-guardrail` is one line in your MCP config, zero runtime dependencies.

## Threat model & limitations

This is **defense-in-depth, not a guarantee**. Regex + entropy detection cannot catch every secret (novel formats, low-entropy passwords outside a `NAME=value` context, base64-encoded or split values, names in free text). It reduces accidental leakage into LLM contexts; it does not replace secret-store hygiene, least-privilege server scoping, or access controls.

Known trade-offs:

- Redaction also applies to file *names* and paths in listings. If a folder is named after an email address, the model sees `[REDACTED:EMAIL]` and can't open it by name. Fix it per tool, e.g. `"tools": { "list_directory": { "disable": ["email"] } }`.
- Test card numbers (e.g. `4111 1111 1111 1111`) and example secrets in docs look exactly like real ones and are redacted unless you add them to `allow`.
- `--dry-run` really does forward everything, secrets included. Use it to evaluate, not in production.
- Only the stdio transport is supported; Streamable HTTP is on the roadmap.

## Development

```bash
npm install
npm test           # unit, regression and ReDoS tests (node:test via tsx)
npm run test:e2e   # builds, then drives the CLI with the official MCP SDK client
                   # against @modelcontextprotocol/server-filesystem and a fault-injecting fake server
npm run build      # emits dist/
```

Test fixtures assemble fake secrets from string pieces so GitHub push protection and other secret scanners don't flag the repository.

Releases are published by GitHub Actions (`.github/workflows/release.yml`) when a GitHub release is published, using npm trusted publishing: no npm token is stored in the repository, and every version carries a provenance attestation linking it to the exact commit and workflow run.

## License

MIT
