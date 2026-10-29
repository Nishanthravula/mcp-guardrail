// One test per finding from the v0.1.0 regression/UAT round. Fake secrets are
// assembled from pieces so repository secret scanners don't flag this file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer, LineBuffer, isSensitiveKey } from "../src/index.js";

const s = new Sanitizer();
const red = (input: string) => s.sanitizeString(input).output;
const leaks = (input: string, secret: string) => red(input).includes(secret);

// ---------------------------------------------------------------- secrets

test("env-style names with a prefix are caught (DB_PASSWORD, JWT_SECRET, ...)", () => {
  const cases: [string, string][] = [
    ["DB_PASSWORD=", "Winter2026Prod!Acme"],
    ["JWT_SECRET=", "8f3kQ9mZ2vL7xR4tN1bW6cY0pH5sJ3dG"],
    ["SESSION_SECRET=", "a7Kq2mX9vL4tR8nB3cF6hJ1s"],
    ["ACCESS_TOKEN: ", "a7Kq2mX9vL4tR8nB3cF6hJ1s"],
    ["STRIPE_API_KEY=", "a7Kq2mX9vL4tR8nB3cF6hJ1s"],
    ['"client_secret": "', 'Zx81kQm2Lp9vR4tW"'],
    ["apiKey: '", "Zx81kQm2Lp9vR4tW'"],
    ["password: ", "Summer2024!"],
    ["password = ", "correct-horse-battery-staple"],
    ['"private_key_id": "', '3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a"'],
  ];
  for (const [name, value] of cases) {
    const bare = value.replace(/["']$/, "");
    assert.ok(!leaks(name + value, bare), `${name}${value} leaked: ${red(name + value)}`);
  }
});

test("code that merely mentions secrets is left alone", () => {
  for (const line of [
    "client_secret: options.clientSecret,",
    "refreshToken: tokens.refresh_token,",
    "const hasClientSecret = clientInformation.client_secret !== undefined;",
    "schema = z.object({ refresh_token: z.string(), scope: z.string() })",
    "token = require_helper_cookie_index.getCookie(ctx, options.cookie);",
    "init.credentials = this.withCredentials ? 'include' : 'same-origin'",
    "readonly token: SyntaxKind.ExtendsKeyword | SyntaxKind.ImplementsKeyword;",
    "PWD: '/Users/maciej',",
    '"Unexpected_token_1012": "Неожиданный токен.",',
    "Our token budget is 50,000 tokens per day.",
    "Set `password=` in your local .env (see .env.example).",
    "password = changeme",
    "API_KEY=${API_KEY}",
    "token: <your-token-here>",
    "TOKEN_URL=https://auth.example.com/oauth/token",
    "next_page_token: CgQIARAB0x9f",
  ]) {
    assert.equal(red(line), line, `false positive on: ${line}`);
  }
});

test("structuredContent: values under sensitive keys are redacted", () => {
  const { value } = s.sanitize({
    user: "acme_admin",
    db_password: "Winter2026Prod!Acme",
    api_key: "x7Qm2vL9tW4nB8cF3hJ6sD1gY5zA",
    nested: { accessToken: "short", headers: { Authorization: "Basic abc" } },
    password: "${DB_PASSWORD}", // reference, not a secret
  });
  assert.deepEqual(value, {
    user: "acme_admin",
    db_password: "[REDACTED:SECRET]",
    api_key: "[REDACTED:SECRET]",
    nested: { accessToken: "[REDACTED:SECRET]", headers: { Authorization: "[REDACTED:SECRET]" } },
    password: "${DB_PASSWORD}",
  });
});

test("protocol handles under token-like keys are NOT redacted", () => {
  for (const k of ["progressToken", "next_page_token", "nextPageToken", "pageToken", "token_type", "max_tokens", "total_tokens", "tokenizer"])
    assert.equal(isSensitiveKey(k), false, k);
  for (const k of ["password", "db_password", "apiKey", "api_key", "accessToken", "refresh_token", "clientSecret", "Authorization", "secret"])
    assert.equal(isSensitiveKey(k), true, k);
});

test("URL credentials: empty username and token-only userinfo", () => {
  const redis = red("redis://:R3d1sP4ssw0rdXyz@cache.acme.internal:6379/0");
  assert.equal(redis, "redis://[REDACTED:CONNECTION_STRING_CREDENTIALS]@cache.acme.internal:6379/0");
  const dsn = red("https://4f8a2c9e1b7d4e6f@o123456.ingest.sentry.io/789012");
  assert.equal(dsn, "https://[REDACTED:URL_CREDENTIALS]@o123456.ingest.sentry.io/789012");
});

test("bearer and basic auth headers", () => {
  assert.equal(red("Authorization: Bearer 8f3kQ9mZ2vL7xR4tN1bW6cY0pH5sJ3dG"), "Authorization: Bearer [REDACTED:BEARER_TOKEN]");
  const basic = Buffer.from("admin:hunter2secret").toString("base64");
  assert.equal(red(`Authorization: Basic ${basic}`), "Authorization: Basic [REDACTED:BASIC_AUTH]");
  assert.equal(red("Basic configuration is required"), "Basic configuration is required");
});

test("--max-string redacts first, so a cut never leaves part of a secret", () => {
  const capped = new Sanitizer({ maxStringLength: 30 });
  const tok = "ghp_" + "R8xK2mQ9vL4tW7nB3cF6hJ1sD5gY0zAqP3eT";
  const out = capped.sanitize({ t: `config: GITHUB_TOKEN=${tok}` }).value.t;
  assert.ok(!out.includes("ghp_R8x"), out);
  assert.match(out, /TRUNCATED/);
});

// ---------------------------------------------------------------- PII

test("phone numbers (NANP and E.164)", () => {
  for (const p of ["(512) 555-0147", "+1-214-555-0199", "972.555.0123", "+1 512 555 0147", "+44 20 7946 0958"])
    assert.equal(red(`call ${p} now`), "call [REDACTED:PHONE] now", p);
  for (const notPhone of ["2026-10-28", "524-71-9038", "192.168.1.44", "v1.2.3", "store=19403", "555-0147"])
    assert.ok(!red(notPhone).includes("PHONE"), notPhone);
});

test("credit cards: brand + Luhn, no swallowed separator", () => {
  assert.equal(red("order 4012888888881881 created"), "order [REDACTED:CREDIT_CARD] created");
  assert.equal(red("Amex 378282246310005."), "Amex [REDACTED:CREDIT_CARD].");
  assert.equal(red("MC 5425-2334-3010-9903"), "MC [REDACTED:CREDIT_CARD]");
  // Luhn-valid but not a card network prefix/length
  assert.equal(red("ts=1761660133733"), "ts=1761660133733");
  assert.equal(red("sku=4006381333931"), "sku=4006381333931");
});

test("IPv4: versions and documentation ranges are not addresses", () => {
  assert.equal(red("ver=4.2.0.1"), "ver=4.2.0.1");
  assert.equal(red("version 10.2.3.4"), "version 10.2.3.4");
  assert.equal(red("v1.2.3.4"), "v1.2.3.4");
  assert.equal(red("see 192.0.2.10 in the RFC"), "see 192.0.2.10 in the RFC");
  assert.equal(red("dotted 1.2.3.4.5"), "dotted 1.2.3.4.5");
  assert.equal(red("host 10.20.30.40."), "host [REDACTED:IPV4].");
});

test("IPv6: compressed and mapped forms; MACs, times and code untouched", () => {
  assert.equal(red("ip 2601:646:8a80:3c0::1f,x"), "ip [REDACTED:IPV6],x");
  assert.equal(red("[::ffff:129.144.52.38]:80"), "[[REDACTED:IPV6]]:80");
  assert.equal(red("fe80::1ff:fe23:4567:890a%eth0"), "[REDACTED:IPV6]%eth0");
  for (const keep of ["mac=00:1A:2B:3C:4D:5E", "at 12:30:45 today", "std::vector<int>", "Foo::Bar", "loop ::1", "doc 2001:db8::1", "SHA256:ab:cd:ef:01:23:45:67:89"])
    assert.equal(red(keep), keep, keep);
});

test("email: URL userinfo is not an email; normal emails are", () => {
  assert.equal(red("mail jane.doe@example.com"), "mail [REDACTED:EMAIL]");
  assert.equal(red("ssh://git@github.com/x"), "ssh://git@github.com/x");
});

// ---------------------------------------------------------------- framing

test("LineBuffer: multi-byte UTF-8 split across chunks is not corrupted", () => {
  const text = JSON.stringify({ t: "café — 日本語 — 🚀 — naïve résumé" }) + "\n";
  const bytes = Buffer.from(text, "utf8");
  const lb = new LineBuffer();
  const lines: string[] = [];
  for (const b of bytes) lb.push(Buffer.from([b]), (l) => lines.push(l));
  assert.deepEqual(lines, [text.trimEnd()]);
});

test("LineBuffer: flush emits a final line with no trailing newline", () => {
  const lb = new LineBuffer();
  const lines: string[] = [];
  lb.push(Buffer.from('{"a":1}\n{"b":2}'), (l) => lines.push(l));
  assert.deepEqual(lines, ['{"a":1}']);
  lb.flush((l) => lines.push(l));
  assert.deepEqual(lines, ['{"a":1}', '{"b":2}']);
});

test("LineBuffer: 20 MB message in 64 KB chunks is linear", () => {
  const big = Buffer.from(JSON.stringify({ t: "x".repeat(20 * 1024 * 1024) }) + "\n");
  const lb = new LineBuffer();
  let got = 0;
  const t0 = performance.now();
  for (let i = 0; i < big.length; i += 65536) lb.push(big.subarray(i, i + 65536), (l) => (got = l.length));
  const ms = performance.now() - t0;
  assert.equal(got, big.length - 1);
  assert.ok(ms < 1500, `took ${ms.toFixed(0)} ms`);
});
