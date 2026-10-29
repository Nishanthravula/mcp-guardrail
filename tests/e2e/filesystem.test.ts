// UAT: a real MCP client -> mcp-guardrail (built CLI) -> the official
// filesystem MCP server, reading and writing a realistic project.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { S, makeFixture, connect, text } from "./helpers.js";

let root: string;
let client: Client;
let raw: Client;
const read = async (c: Client, rel: string) =>
  c.callTool({ name: "read_text_file", arguments: { path: path.join(root, rel) } });

before(async () => {
  root = makeFixture();
  client = await connect(root);
  raw = await connect(root, [], false);
});
after(async () => {
  await client?.close();
  await raw?.close();
  fs.rmSync(root, { recursive: true, force: true });
});

test("every planted secret and PII value is redacted (text and structuredContent)", async () => {
  const mustHide: [string, string][] = [
    [".env", S.awsId], [".env", S.awsSecret], [".env", S.anthropic], [".env", S.openai],
    [".env", S.github], [".env", S.stripe], [".env", S.slack], [".env", S.google],
    [".env", S.pgPass], [".env", S.redisPass], [".env", S.dbPassword], [".env", S.jwtSecret],
    [".env", S.sessionSecret], [".env", S.sentryKey],
    ["config/database.yml", S.pgPass], ["config/database.yml", "10.20.30.40"],
    ["config/service-account.json", S.pemBody], ["config/service-account.json", S.keyId],
    ["config/service-account.json", "deploy-bot@"],
    ["keys/id_ed25519", S.sshBody],
    ["data/customers.csv", "maria.lopez@gmail.com"], ["data/customers.csv", "524-71-9038"],
    ["data/customers.csv", "4539 1488 0343 6467"], ["data/customers.csv", "5425-2334-3010-9903"],
    ["data/customers.csv", "378282246310005"], ["data/customers.csv", "555-0147"],
    ["data/customers.csv", "214-555-0199"], ["data/customers.csv", "972.555.0123"],
    ["data/customers.csv", "73.162.44.201"], ["data/customers.csv", "2601:646:8a80:3c0::1f"],
    ["data/customers.csv", "::1f"], ["logs/app.log", S.jwt.split(".")[0]],
    ["logs/app.log", "maria.lopez"], ["logs/app.log", "4012888888881881"],
  ];
  const leaks: string[] = [];
  for (const [file, secret] of mustHide) {
    assert.ok(text(await read(raw, file)).includes(secret), `fixture missing ${secret} in ${file}`);
    const r = await read(client, file);
    if (JSON.stringify(r).includes(secret)) leaks.push(`${file}: ${secret}`);
  }
  assert.deepEqual(leaks, []);
});

test("benign look-alikes pass through unchanged", async () => {
  const mustKeep: [string, string][] = [
    ["logs/app.log", "550e8400-e29b-41d4-a716-446655440000"], ["logs/app.log", "2026-10-28T14:02:11.482Z"],
    ["logs/app.log", "ts=1761660133733"], ["logs/app.log", "sku=4006381333931"],
    ["logs/app.log", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"], ["logs/app.log", "ver=4.2.0.1"],
    ["logs/app.log", "mac=00:1A:2B:3C:4D:5E"], ["logs/app.log", "payments.acme.internal"],
    ["logs/app.log", "order [REDACTED:CREDIT_CARD] created"], // separator kept
    ["package-lock.json", "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ"],
    ["package-lock.json", "4.17.21"], ["src/theme.css", "#1f6feb"],
    ["src/auth.ts", "client_secret: options.clientSecret"], ["src/auth.ts", "refreshToken: tokens.refresh_token"],
    ["README.md", "50,000 tokens per day"], ["README.md", "Set `password=` in your local .env"],
    ["README.md", "https://docs.acme.io/setup"], ["config/service-account.json", "acme-prod-381204"],
    [".env", "@db.acme.internal:5432/orders"], [".env", "@cache.acme.internal:6379/0"],
    [".env", "@o123456.ingest.sentry.io/789012"],
  ];
  for (const [file, keep] of mustKeep) {
    assert.ok(text(await read(client, file)).includes(keep), `${file}: "${keep}" was altered`);
  }
});

test("150 KB multilingual file is byte-identical through the proxy", async () => {
  const want = fs.readFileSync(path.join(root, "data/i18n-notes.md"), "utf8");
  for (let i = 0; i < 3; i++) assert.equal(text(await read(client, "data/i18n-notes.md")), want);
});

test("images pass through byte-identical", async () => {
  const args = { name: "read_media_file", arguments: { path: path.join(root, "logo.png") } };
  const a = (await raw.callTool(args)) as { content: { data: string }[] };
  const b = (await client.callTool(args)) as { content: { data: string }[] };
  assert.equal(b.content[0].data, a.content[0].data);
});

// ---------------------------------------------------------------- write path

const envPath = () => path.join(root, ".env");

test("A: rewriting a file the model only saw redacted is blocked; disk untouched", async () => {
  const before = fs.readFileSync(envPath(), "utf8");
  const seen = text(await read(client, ".env"));
  const r = await client.callTool({
    name: "write_file",
    arguments: { path: envPath(), content: seen.replace("NODE_ENV=production", "NODE_ENV=staging") },
  });
  assert.equal(r.isError, true);
  assert.match(text(r), /blocked this request.*redaction placeholder/);
  assert.equal(fs.readFileSync(envPath(), "utf8"), before);
});

test("B: a targeted edit works and its diff is redacted", async () => {
  const before = fs.readFileSync(envPath(), "utf8");
  const r = await client.callTool({
    name: "edit_file",
    arguments: { path: envPath(), edits: [{ oldText: "NODE_ENV=production", newText: "NODE_ENV=staging" }] },
  });
  assert.ok(!r.isError, text(r));
  assert.equal(fs.readFileSync(envPath(), "utf8"), before.replace("NODE_ENV=production", "NODE_ENV=staging"));
  assert.ok(!JSON.stringify(r).includes(S.awsId));
  fs.writeFileSync(envPath(), before);
});

test("B2: default mode still lets the user rotate a token the model was given", async () => {
  const before = fs.readFileSync(envPath(), "utf8");
  const next = "ghp" + "_N3wT0k3nAbCdEfGhIjKlMnOpQrStUvWxYz12";
  const r = await client.callTool({
    name: "edit_file",
    arguments: { path: envPath(), edits: [{ oldText: `GITHUB_TOKEN=${S.github}`, newText: `GITHUB_TOKEN=${next}` }] },
  });
  assert.ok(!r.isError, text(r));
  assert.ok(fs.readFileSync(envPath(), "utf8").includes(`GITHUB_TOKEN=${next}`));
  assert.ok(!JSON.stringify(r).includes(next), "new token echoed back unredacted");
  fs.writeFileSync(envPath(), before);
});

test("C/D: --both blocks secrets going to the server, never rewrites them", async () => {
  const both = await connect(root, ["--both"]);
  try {
    const before = fs.readFileSync(envPath(), "utf8");
    const add = await both.callTool({
      name: "edit_file",
      arguments: { path: envPath(), edits: [{ oldText: "NODE_ENV=production", newText: `NODE_ENV=production\nNEW_TOKEN=${"ghp" + "_N3wT0k3nAbCdEfGhIjKlMnOpQrStUvWxYz12"}` }] },
    });
    assert.equal(add.isError, true);
    assert.match(text(add), /contain a secret \(GITHUB_TOKEN\)/);
    assert.equal(fs.readFileSync(envPath(), "utf8"), before);
  } finally {
    await both.close();
  }
});

test("E: --both does not mangle paths that contain an email address", async () => {
  fs.mkdirSync(path.join(root, "exports/maria.lopez@gmail.com"), { recursive: true });
  fs.writeFileSync(path.join(root, "exports/maria.lopez@gmail.com/notes.txt"), "hello");
  const both = await connect(root, ["--both"]);
  try {
    const r = await read(both, "exports/maria.lopez@gmail.com/notes.txt");
    assert.ok(!r.isError, text(r));
    assert.equal(text(r), "hello");
  } finally {
    await both.close();
  }
});
