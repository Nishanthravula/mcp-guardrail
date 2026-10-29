// Shared setup for end-to-end tests: a realistic project full of fake
// secrets/PII, and a real MCP client talking to the built CLI.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const require = createRequire(import.meta.url);
export const ROOT_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
export const CLI = path.join(ROOT_DIR, "dist/cli.js");
export const FAKE_SERVER = path.join(ROOT_DIR, "tests/e2e/fake-server.mjs");
export const FS_SERVER = require.resolve("@modelcontextprotocol/server-filesystem/dist/index.js");

// Fake secrets in real formats, assembled so secret scanners don't flag the repo.
export const S = {
  awsId: "AKIA" + "4HKQ7R2ZXM3PLQ8W",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzX9q2Lm4Tz",
  anthropic: "sk-ant-" + "api03-Xq7vR2mK9pL4tW8nB3cF6hJ1sD5gY0zA-Qw3eRt7Uy",
  openai: "sk-" + "proj-4fT9xQ2mW7rL1vB8kN3pZ6cH0sJ5yG2dE9aR",
  github: "ghp" + "_R8xK2mQ9vL4tW7nB3cF6hJ1sD5gY0zAqP3eT",
  stripe: "sk_" + "live_51Hx9QmK2vL7tR4nB8cF3hJ6sD1gY5zA",
  slack: "xoxb" + "-2847193650-4829173650281-Kq8mR2vL9tW4nB7cF3hJ6sD1",
  google: "AIza" + "SyD4kR9mQ2vL7tW1nB8cF3hJ6sD0gY5zAqP",
  pgPass: "Pr0d-Db!s3cret-2026",
  redisPass: "R3d1sP4ssw0rdXyz",
  dbPassword: "Winter2026Prod!Acme",
  jwtSecret: "8f3kQ9mZ2vL7xR4tN1bW6cY0pH5sJ3dG",
  sessionSecret: "a7Kq2mX9vL4tR8nB3cF6hJ1s",
  sentryKey: "4f8a2c9e1b7d4e6f",
  pemBody: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
  sshBody: "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
  keyId: "3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a",
  jwt:
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
    "eyJzdWIiOiJ1c2VyXzEwMDIxIiwiZXhwIjoxNzYxNjYzNzMzfQ." +
    "dGhpc2lzbm90YXJlYWxzaWduYXR1cmVidXRsb29rc2xpa2VvbmU",
};

export function makeFixture(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardrail-e2e-"));
  const w = (rel: string, text: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  };
  w(".env", [
    "NODE_ENV=production",
    `AWS_ACCESS_KEY_ID=${S.awsId}`,
    `AWS_SECRET_ACCESS_KEY=${S.awsSecret}`,
    `ANTHROPIC_API_KEY=${S.anthropic}`,
    `OPENAI_API_KEY=${S.openai}`,
    `GITHUB_TOKEN=${S.github}`,
    `STRIPE_SECRET_KEY=${S.stripe}`,
    `SLACK_BOT_TOKEN=${S.slack}`,
    `GOOGLE_MAPS_KEY=${S.google}`,
    `DATABASE_URL=postgres://acme_admin:${S.pgPass}@db.acme.internal:5432/orders`,
    `REDIS_URL=redis://:${S.redisPass}@cache.acme.internal:6379/0`,
    `DB_PASSWORD=${S.dbPassword}`,
    `JWT_SECRET=${S.jwtSecret}`,
    `SESSION_SECRET=${S.sessionSecret}`,
    `SENTRY_DSN=https://${S.sentryKey}@o123456.ingest.sentry.io/789012`,
    "",
  ].join("\n"));
  w("config/database.yml", `production:\n  adapter: postgresql\n  host: 10.20.30.40\n  username: acme_admin\n  password: "${S.pgPass}"\n  pool: 25\n`);
  w("config/service-account.json", JSON.stringify({
    type: "service_account",
    project_id: "acme-prod-381204",
    private_key_id: S.keyId,
    private_key: `-----BEGIN PRIVATE KEY-----\n${S.pemBody}\n-----END PRIVATE KEY-----\n`,
    client_email: "deploy-bot@acme-prod-381204.iam.gserviceaccount.com",
    client_id: "104857392018475629301",
  }, null, 2));
  w("keys/id_ed25519", `-----BEGIN OPENSSH PRIVATE KEY-----\n${S.sshBody}\n-----END OPENSSH PRIVATE KEY-----\n`);
  w("data/customers.csv", [
    "customer_id,name,email,phone,ssn,card,signup_ip",
    "C-10021,Maria Lopez,maria.lopez@gmail.com,(512) 555-0147,524-71-9038,4539 1488 0343 6467,73.162.44.201",
    "C-10022,James Chen,j.chen@outlook.com,+1-214-555-0199,318-62-4471,5425-2334-3010-9903,2601:646:8a80:3c0::1f",
    "C-10023,Priya Shah,priya.shah@acme.io,972.555.0123,601-28-5517,378282246310005,192.168.1.44",
    "",
  ].join("\n"));
  w("logs/app.log", [
    "2026-10-28T14:02:11.482Z INFO  request_id=550e8400-e29b-41d4-a716-446655440000 GET /api/orders 200 41ms",
    "2026-10-28T14:02:12.019Z INFO  user login ok user=maria.lopez@gmail.com ip=73.162.44.201",
    "2026-10-28T14:02:13.733Z WARN  retry upstream http://payments.acme.internal attempt=2 ts=1761660133733",
    `2026-10-28T14:02:14.101Z DEBUG outgoing headers Authorization: Bearer ${S.jwt}`,
    "2026-10-28T14:02:15.550Z INFO  order 4012888888881881 created sku=4006381333931 store=19403",
    "2026-10-28T14:02:16.002Z INFO  build commit=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b node=v22.23.4 ver=4.2.0.1",
    "2026-10-28T14:02:17.300Z INFO  device mac=00:1A:2B:3C:4D:5E connected port 8443",
    "",
  ].join("\n"));
  w("package-lock.json", JSON.stringify({ name: "acme-app", lockfileVersion: 3, packages: { "node_modules/lodash": {
    version: "4.17.21",
    resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
    integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==",
  } } }, null, 2));
  w("src/theme.css", ":root { --brand: #1f6feb; --accent: #ffd33d; }\n");
  w("src/auth.ts", "export const cfg = {\n  client_secret: options.clientSecret,\n  refreshToken: tokens.refresh_token,\n};\n");
  w("README.md", "# Acme App\nContact the team at support@acme.io. Our token budget is 50,000 tokens per day.\nSet `password=` in your local .env (see .env.example). Default port 8080, version 1.2.3.\nDocs: https://docs.acme.io/setup\n");
  const words = ["日本語のテキスト", "café", "naïve", "résumé", "Ñandú", "Москва", "🚀", "données", "Größe", "العربية"];
  let notes = "";
  for (let i = 0; notes.length < 150_000; i++) notes += words[(i * 7) % words.length] + " ";
  w("data/i18n-notes.md", notes);
  // A small valid PNG (1x1, red)
  fs.writeFileSync(path.join(dir, "logo.png"), Buffer.from(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944415408d763f8cfc0000003010100c9fe92ef0000000049454e44ae426082", "hex"));
  return dir;
}

export async function connect(root: string, flags: string[] = [], guarded = true) {
  const transport = new StdioClientTransport(
    guarded
      ? { command: process.execPath, args: [CLI, "--quiet", ...flags, "--", process.execPath, FS_SERVER, root], stderr: "pipe" }
      : { command: process.execPath, args: [FS_SERVER, root], stderr: "pipe" },
  );
  const client = new Client({ name: "guardrail-e2e", version: "1.0.0" });
  await client.connect(transport);
  return client;
}

export function text(result: unknown): string {
  const r = result as { content?: { text?: string }[] };
  return (r.content ?? []).map((c) => c.text ?? "").join("");
}
