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

Wrap any stdio MCP server by prefixing its command:

```jsonc
// Claude Desktop / Claude Code MCP config
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y", "mcp-guardrail", "--",
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

## CLI options

```
mcp-guardrail [flags] -- <server-command> [args...]

  --both              sanitize both directions (default: server→client only)
  --max-string N      truncate any string value longer than N characters
  --disable id1,id2   disable specific rules (e.g. --disable email,ipv4)
  --quiet             suppress stderr redaction logs
```

## What it detects

| Category | Rules |
|---|---|
| Cloud & vendor keys | AWS access key IDs & secret keys, Anthropic, OpenAI, Google, Stripe, Slack, GitHub tokens/PATs |
| Crypto material | JWTs, PEM private key blocks |
| Credentials | `user:password@` in connection strings, entropy-gated `password=`/`token=`/`secret=` assignments |
| PII | Emails, SSNs, credit cards (Luhn-validated), public IPv4/IPv6 |

False-positive controls: credit cards must pass Luhn, generic assigned secrets must clear a Shannon-entropy threshold, loopback/broadcast IPs are ignored, and overlapping matches resolve to the most specific rule via single-pass range redaction (placeholders can never be re-matched).

## Library usage

```ts
import { Sanitizer } from "mcp-guardrail";

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
import { GuardrailProxy } from "mcp-guardrail";

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

This is **defense-in-depth, not a guarantee**. Regex + entropy detection cannot catch every secret (novel formats, secrets split across chunks, encoded values). It reduces accidental leakage into LLM contexts; it does not replace secret-store hygiene, least-privilege server scoping, or access controls. Currently supports the stdio transport; HTTP/SSE is on the roadmap.

## Development

```bash
npm install
npm test        # node:test suite via tsx
npm run build   # emits dist/
```

## License

MIT
