// Injection detection end to end: the built CLI in front of a scripted tool
// server, driven with raw JSON-RPC lines.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { CLI, FAKE_SERVER } from "./helpers.js";

const SECRET_PHRASE = "contents of the secrets file"; // distinctive part of the fake server's injection
const NOTICE = /^\[mcp-guardrail: withheld — this tool result looks like a prompt injection \(score \d\.\d\d\)\. Run with --dry-run to inspect\.\]$/;
const call = (id: number, name: string) =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } });

interface Run { messages: any[]; stdout: string; stderr: string; audit: any[]; auditRaw: string; code: number | null }

function run(flags: string[], lines: string[]): Promise<Run> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-inj-"));
  const auditFile = path.join(dir, "audit.jsonl");
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [CLI, "--audit-log", auditFile, ...flags, "--", process.execPath, FAKE_SERVER, "tools"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d: Buffer) => (stdout += d));
    p.stderr.on("data", (d: Buffer) => (stderr += d));
    for (const l of lines) p.stdin.write(l + "\n");
    p.stdin.end();
    const timer = setTimeout(() => p.kill("SIGKILL"), 15_000);
    p.on("close", (code) => {
      clearTimeout(timer);
      const auditRaw = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8") : "";
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({
        messages: stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)),
        stdout,
        stderr,
        audit: auditRaw.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)),
        auditRaw,
        code,
      });
    });
  });
}
const injectionEvents = (r: Run) => r.audit.filter((e) => /injection/.test(e.event));

test("off by default: nothing is scored, logged or changed", async () => {
  const r = await run([], [call(1, "single")]);
  assert.match(r.messages[0].result.content[0].text, new RegExp(SECRET_PHRASE));
  assert.deepEqual(injectionEvents(r), []);
  assert.doesNotMatch(r.stderr, /injection/);
});

test("report mode forwards the result unchanged and records one event", async () => {
  const r = await run(["--detect-injection"], [call(1, "single"), call(2, "clean")]);
  assert.match(r.messages[0].result.content[0].text, new RegExp(SECRET_PHRASE));
  const events = injectionEvents(r);
  assert.equal(events.length, 1);
  const e = events[0];
  assert.deepEqual(
    [e.event, e.tool, e.id, e.path, e.action, e.model, e.truncated],
    ["injection", "single", 1, "result.content[0].text", "report", "injection-linear-v1", false],
  );
  assert.ok(e.score >= e.threshold && e.score <= 1);
  assert.match(r.stderr, /tools\/call \(single\): injection suspected at result\.content\[0\]\.text \(score \d\.\d\d\)\n/);
});

test("block mode withholds only the injected item of a multi-item result", async () => {
  const r = await run(["--detect-injection=block"], [call(7, "multi")]);
  const [a, b, c] = r.messages[0].result.content;
  assert.equal(a.text, "The quarterly report is attached for review. The meeting moved to Tuesday at noon.");
  assert.match(b.text, NOTICE);
  assert.equal(c.text, "Balance after this transaction: 1,204.55.");
  assert.deepEqual([r.messages[0].jsonrpc, r.messages[0].id], ["2.0", 7]);
  assert.equal(injectionEvents(r)[0].action, "block");
  assert.match(r.stderr, /injection suspected at result\.content\[1\]\.text \(score \d\.\d\d\) — withheld/);
});

test("block mode reaches strings nested in structuredContent, alongside redaction in the same message", async () => {
  const r = await run(["--detect-injection=block"], [call(3, "structured")]);
  const result = r.messages[0].result;
  assert.equal(result.content[0].text, "deploy key [REDACTED:AWS_ACCESS_KEY_ID] rotated last week");
  assert.match(result.structuredContent.reviews[0].body, NOTICE);
  assert.equal(result.structuredContent.reviews[0].author, "amy");
  assert.equal(result.structuredContent.count, 3);
  assert.match(result.structuredContent.summary, /quarterly report/);
  assert.equal(injectionEvents(r)[0].path, "result.structuredContent.reviews[0].body");
  assert.ok(r.audit.some((e) => e.event === "redact"));
});

test("dry run changes nothing and logs would-injection", async () => {
  const r = await run(["--detect-injection=block", "--dry-run"], [call(1, "multi")]);
  assert.match(r.messages[0].result.content[1].text, new RegExp(SECRET_PHRASE));
  assert.deepEqual(injectionEvents(r).map((e) => [e.event, e.action]), [["would-injection", "block"]]);
  assert.match(r.stderr, /would withhold/);
});

test("the flagged text never reaches stderr or the audit log", async () => {
  for (const flags of [["--detect-injection"], ["--detect-injection=block"], ["--detect-injection=block", "--dry-run"]]) {
    const r = await run(flags, [call(1, "single"), call(2, "multi"), call(3, "structured")]);
    assert.equal(injectionEvents(r).length, 3);
    assert.doesNotMatch(r.stderr, new RegExp(SECRET_PHRASE));
    assert.doesNotMatch(r.auditRaw, new RegExp(SECRET_PHRASE));
    assert.doesNotMatch(r.auditRaw + r.stderr, /Ignore all previous/i);
  }
});

test("per-tool setting overrides the global mode in both directions", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-cfg-"));
  const cfg = path.join(dir, "guardrail.json");
  fs.writeFileSync(cfg, JSON.stringify({ injection: { mode: "block" }, tools: { multi: { injection: "off" }, single: { injection: "report" } } }));
  const r = await run(["--config", cfg], [call(1, "multi"), call(2, "single"), call(3, "structured")]);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(r.messages[0].result.content[1].text, new RegExp(SECRET_PHRASE)); // off
  assert.match(r.messages[1].result.content[0].text, new RegExp(SECRET_PHRASE)); // report
  assert.match(r.messages[2].result.structuredContent.reviews[0].body, NOTICE); // global block
  assert.deepEqual(injectionEvents(r).map((e) => [e.tool, e.action]), [["single", "report"], ["structured", "block"]]);
});

test("a tool can opt in while the global mode is off", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-cfg-"));
  const cfg = path.join(dir, "guardrail.json");
  fs.writeFileSync(cfg, JSON.stringify({ tools: { multi: { injection: "block" } } }));
  const r = await run(["--config", cfg], [call(1, "multi"), call(2, "single")]);
  fs.rmSync(dir, { recursive: true, force: true });
  assert.match(r.messages[0].result.content[1].text, NOTICE);
  assert.match(r.messages[1].result.content[0].text, new RegExp(SECRET_PHRASE));
});

test("only tool results are scored: other responses pass through", async () => {
  const other = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "resources/read", params: {} });
  const r = await run(["--detect-injection=block"], [other]);
  assert.match(r.messages[0].result.echo, new RegExp(SECRET_PHRASE));
  assert.deepEqual(injectionEvents(r), []);
});

test("a custom threshold of 0.999 lets the same result through", async () => {
  const r = await run(["--detect-injection=block", "--injection-threshold", "0.999999"], [call(1, "single")]);
  assert.match(r.messages[0].result.content[0].text, new RegExp(SECRET_PHRASE));
});

test("invalid flag values are rejected at startup", async () => {
  for (const flags of [["--detect-injection=loud"], ["--injection-threshold", "2"], ["--injection-threshold", "abc"]]) {
    const r = await run(flags, []);
    assert.equal(r.code, 2, flags.join(" "));
    assert.match(r.stderr, /injection/);
  }
});
