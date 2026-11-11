import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  Sanitizer,
  DEFAULT_RULES,
  validateConfig,
  loadConfig,
  compileRules,
  findSlowRules,
  ConfigError,
} from "../src/index.js";

const rejects = (raw: unknown, re: RegExp) =>
  assert.throws(() => validateConfig(raw), (e: unknown) => e instanceof ConfigError && re.test((e as Error).message));

test("a valid config passes", () => {
  const c = validateConfig({
    both: true,
    maxStringLength: 20000,
    disable: ["phone", "sensitive-key"],
    categories: ["secret"],
    allow: ["support@acme.io"],
    allowPatterns: ["10\\.0\\.\\d+\\.\\d+"],
    rules: [{ id: "acme-key", pattern: "acme_[A-Za-z0-9]{32}", label: "ACME_KEY" }],
    tools: { read_media_file: { skip: true }, fetch: { disable: ["email", "acme-key"] } },
    dryRun: false,
    auditLog: "audit.jsonl",
    quiet: true,
  });
  assert.equal(c.rules?.[0].id, "acme-key");
});

test("typos fail loudly with a suggestion", () => {
  rejects({ dissable: ["email"] }, /unknown key "dissable" \(did you mean "disable"\?\)/);
  rejects({ disable: ["emial"] }, /unknown rule id "emial" \(did you mean "email"\?\)/);
  rejects({ tools: { fetch: { skp: true } } }, /tools\["fetch"\]: unknown key "skp" \(did you mean "skip"\?\)/);
  rejects({ tools: { fetch: { disable: ["phon"] } } }, /unknown rule id "phon" \(did you mean "phone"\?\)/);
  rejects({ rules: [{ id: "x", pattern: "x{3}", lable: "X" }] }, /unknown key "lable" \(did you mean "label"\?\)/);
});

test("bad values are rejected with precise messages", () => {
  rejects([], /must be a JSON object/);
  rejects({ both: "yes" }, /"both" must be true or false/);
  rejects({ maxStringLength: -1 }, /non-negative integer/);
  rejects({ categories: ["secrets"] }, /may only contain "secret" and "pii"/);
  rejects({ allowPatterns: ["("] }, /allowPatterns\[0\] is not a valid regex/);
  rejects({ rules: [{ id: "Bad_Id", pattern: "x" }] }, /lowercase letters, digits and dashes/);
  rejects({ rules: [{ id: "email", pattern: "x" }] }, /id "email" is already in use/);
  rejects({ rules: [{ id: "a", pattern: "x" }, { id: "a", pattern: "y" }] }, /id "a" is already in use/);
  rejects({ rules: [{ id: "a", pattern: "(" }] }, /\(a\): invalid regex/);
  rejects({ rules: [{ id: "a", pattern: "x*" }] }, /matches the empty string/);
  rejects({ rules: [{ id: "a", pattern: "k=(\\w+)", group: 2 }] }, /only 1 capture group/);
  rejects({ rules: [{ id: "a", pattern: "x", label: "lower" }] }, /UPPER_SNAKE_CASE/);
  rejects({ rules: [{ id: "a", pattern: "x", flags: "g" }] }, /may only contain i, m, s, u/);
});

test("custom rules: whole match, capture group, entropy gate, case-insensitive flag", () => {
  const extraRules = compileRules([
    { id: "acme-key", pattern: "acme_[A-Za-z0-9]{32}" },
    { id: "acme-pin", pattern: "PIN[=:](\\d{6})", group: 1, label: "PIN", category: "pii", flags: "i" },
    { id: "internal-token", pattern: "itok_[a-z0-9]{12}", minEntropy: 3 },
  ]);
  const s = new Sanitizer({ extraRules });
  const key = "acme_" + "Q7mR2vL9tW4nB8cF3hJ6sD1gY5zAxK0p";
  assert.equal(s.sanitizeString(`key ${key} ok`).output, "key [REDACTED:ACME_KEY] ok");
  assert.equal(s.sanitizeString("pin=482913").output, "pin=[REDACTED:PIN]");
  assert.equal(s.sanitizeString("itok_aaaaaaaaaaaa").output, "itok_aaaaaaaaaaaa"); // low entropy
  assert.equal(s.sanitizeString("itok_q8x2m4v7k1z9").output, "[REDACTED:INTERNAL_TOKEN]");
});

test("allowlist: exact values and whole-value patterns", () => {
  const s = new Sanitizer({
    allow: ["support@acme.io", "4111 1111 1111 1111"],
    allowPatterns: [/10\.0\.\d+\.\d+/, /.*@acme\.io/],
  });
  const red = (t: string) => s.sanitizeString(t).output;
  assert.equal(red("mail support@acme.io"), "mail support@acme.io");
  assert.equal(red("mail sales@acme.io"), "mail sales@acme.io"); // pattern
  assert.equal(red("mail jane@gmail.com"), "mail [REDACTED:EMAIL]");
  assert.equal(red("test card 4111 1111 1111 1111"), "test card 4111 1111 1111 1111");
  assert.equal(red("card 4539 1488 0343 6467"), "card [REDACTED:CREDIT_CARD]");
  assert.equal(red("host 10.0.3.7"), "host 10.0.3.7");
  // a pattern must match the WHOLE value: 10.0.x.x does not allow 110.0.3.7
  assert.equal(red("host 110.0.3.7"), "host [REDACTED:IPV4]");
});

test("allowlist also applies to values under sensitive keys", () => {
  const s = new Sanitizer({ allow: ["demo-password-123"] });
  const { value } = s.sanitize({ password: "demo-password-123", api_key: "x7Qm2vL9tW4nB8cF3hJ6sD1" });
  assert.deepEqual(value, { password: "demo-password-123", api_key: "[REDACTED:SECRET]" });
});

test("details: JSON paths and fingerprints, never values", () => {
  const seen: string[] = [];
  const s = new Sanitizer({ fingerprint: (v) => (seen.push(v), `fp${v.length}`) });
  const awsId = "AKIA" + "4HKQ7R2ZXM3PLQ8W";
  const r = s.sanitize({ result: { content: [{ type: "text", text: `id ${awsId}` }], structuredContent: { "db-password": "Winter2026Prod!Acme" } } });
  assert.deepEqual(r.details, [
    { ruleId: "aws-access-key-id", label: "AWS_ACCESS_KEY_ID", path: "result.content[0].text", fingerprint: "fp20" },
    { ruleId: "sensitive-key", label: "SECRET", path: 'result.structuredContent["db-password"]', fingerprint: "fp19" },
  ]);
  assert.deepEqual(seen, [awsId, "Winter2026Prod!Acme"]);
});

test("loadConfig: relative auditLog resolves next to the config; bad JSON is reported", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "guardrail-cfg-"));
  const file = path.join(dir, "guardrail.json");
  fs.writeFileSync(file, JSON.stringify({ auditLog: "logs/audit.jsonl" }));
  assert.equal(loadConfig(file).auditLog, path.join(dir, "logs/audit.jsonl"));
  fs.writeFileSync(file, "{ \"disable\": [\"email\", ] }");
  assert.throws(() => loadConfig(file), /guardrail\.json" is not valid JSON/);
  assert.throws(() => loadConfig(path.join(dir, "missing.json")), /cannot read config .*ENOENT/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("slow custom regexes are caught at startup, without hanging", async () => {
  const t0 = performance.now();
  const slow = await findSlowRules(
    [
      { id: "ok", pattern: "acme_[A-Za-z0-9]{32}" },
      { id: "nested", pattern: "(a+)+$" },
      { id: "quadratic", pattern: "\\w+\\.\\w+@" },
    ],
    150,
    2000,
  );
  assert.deepEqual(slow.map((s) => s.id), ["nested", "quadratic"]);
  assert.ok(performance.now() - t0 < 8000, "probe must be bounded by its timeout");
});

test("guardrail.schema.json lists exactly the built-in rule ids", () => {
  const schema = JSON.parse(fs.readFileSync(new URL("../guardrail.schema.json", import.meta.url), "utf8"));
  const listed = schema.$defs.ruleIds.items.anyOf[0].enum;
  assert.deepEqual(listed, [...DEFAULT_RULES.map((r) => r.id), "sensitive-key"]);
});

// ---------------------------------------------------------------- injection detection

test("injection: a valid block and per-tool modes are accepted", () => {
  const cfg = validateConfig({
    injection: { mode: "block", threshold: 0.8 },
    tools: { read_text_file: { injection: "report" }, list_directory: { injection: "off" } },
  });
  assert.deepEqual(cfg.injection, { mode: "block", threshold: 0.8 });
  assert.equal(cfg.tools?.read_text_file.injection, "report");
});

test("injection: unknown modes and keys are rejected with a suggestion", () => {
  assert.throws(() => validateConfig({ injection: { mode: "blok" } }), /injection.*"mode".*did you mean "block"/s);
  assert.throws(() => validateConfig({ injection: { mod: "block" } }), /unknown key "mod" \(did you mean "mode"\?\)/);
  assert.throws(() => validateConfig({ injektion: { mode: "block" } }), /did you mean "injection"/);
  assert.throws(() => validateConfig({ tools: { t: { injection: "on" } } }), /tools\["t"\].*"injection"/s);
});

test("injection: threshold must be strictly between 0 and 1", () => {
  for (const threshold of [0, 1, 1.5, -0.1, "0.5", NaN]) {
    assert.throws(() => validateConfig({ injection: { mode: "report", threshold } }), /"threshold"/, String(threshold));
  }
  assert.equal(validateConfig({ injection: { threshold: 0.99 } }).injection?.threshold, 0.99);
});
