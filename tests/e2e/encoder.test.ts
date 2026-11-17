// The optional transformer detector end to end: the built CLI, the tiny test
// model in tests/fixtures/encoder-tiny, and a scripted tool server. The tiny
// model's scores mean nothing, so thresholds are set to flag everything or
// nothing; what is tested is wiring, ordering and failure handling.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { CLI, FAKE_SERVER, ROOT_DIR } from "./helpers.js";

const TINY = path.join(ROOT_DIR, "tests/fixtures/encoder-tiny");
const NOTICE = /^\[mcp-guardrail: withheld — this tool result looks like a prompt injection \(score \d\.\d\d\)\. Run with --dry-run to inspect\.\]$/;
const ERROR_NOTICE = "[mcp-guardrail: withheld — this tool result could not be checked for prompt injection.]";
const SECRET_PHRASE = /contents of the secrets file/;
const call = (id: number, name: string) =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: {} } });
const other = (id: number) => JSON.stringify({ jsonrpc: "2.0", id, method: "resources/read", params: {} });

interface Run { messages: any[]; stderr: string; audit: any[]; code: number | null }

function run(flags: string[], lines: string[], cli = CLI): Promise<Run> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-enc-e2e-"));
  const auditFile = path.join(dir, "audit.jsonl");
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [cli, "--audit-log", auditFile, ...flags, "--", process.execPath, FAKE_SERVER, "tools"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d: Buffer) => (stdout += d));
    p.stderr.on("data", (d: Buffer) => (stderr += d));
    for (const l of lines) p.stdin.write(l + "\n");
    p.stdin.end();
    const timer = setTimeout(() => p.kill("SIGKILL"), 30_000);
    p.on("close", (code) => {
      clearTimeout(timer);
      const raw = fs.existsSync(auditFile) ? fs.readFileSync(auditFile, "utf8") : "";
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({
        messages: stdout.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)),
        stderr,
        audit: raw.trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)),
        code,
      });
    });
  });
}

test("block mode with a model directory withholds scored items and names the model", async () => {
  const r = await run(["--detect-injection=block", "--injection-model", TINY, "--injection-threshold", "0.000001"], [call(1, "multi")]);
  for (const item of r.messages[0].result.content) assert.match(item.text, NOTICE);
  const events = r.audit.filter((e) => e.event === "injection");
  assert.equal(events.length, 3);
  assert.ok(events.every((e) => e.model === "encoder-tiny-test" && e.action === "block"));
});

test("a threshold of 0.999999 lets everything through", async () => {
  const r = await run(["--detect-injection=block", "--injection-model", TINY, "--injection-threshold", "0.999999"], [call(1, "single")]);
  assert.match(r.messages[0].result.content[0].text, SECRET_PHRASE);
  assert.deepEqual(r.audit.filter((e) => /injection/.test(e.event)), []);
});

test("responses keep their order when tool results are scored asynchronously", async () => {
  const lines: string[] = [];
  for (let i = 1; i <= 40; i++) lines.push(i % 2 ? call(i, i % 3 ? "multi" : "single") : other(i));
  const r = await run(["--detect-injection=block", "--injection-model", TINY, "--injection-threshold", "0.000001"], lines);
  assert.deepEqual(r.messages.map((m) => m.id), Array.from({ length: 40 }, (_, i) => i + 1));
  for (const m of r.messages) {
    if (m.id % 2) assert.match(m.result.content[0].text, NOTICE);
    else assert.match(m.result.echo, SECRET_PHRASE); // not a tool result: untouched
  }
});

test("every pending result is written before the proxy exits with the server", async () => {
  const lines = Array.from({ length: 20 }, (_, i) => call(i + 1, "multi"));
  const r = await run(["--detect-injection=report", "--injection-model", TINY], lines);
  assert.equal(r.code, 0);
  assert.equal(r.messages.length, 20);
  assert.equal(r.audit.at(-1).event, "stop");
});

function brokenAtRunTime(): string {
  // Loads fine (model.onnx is intact) but every inference fails: the start
  // token id is outside the vocabulary.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-broken-"));
  for (const f of fs.readdirSync(TINY)) fs.copyFileSync(path.join(TINY, f), path.join(dir, f));
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "guardrail.json"), "utf8"));
  fs.writeFileSync(path.join(dir, "guardrail.json"), JSON.stringify({ ...meta, clsId: 10_000_000 }));
  return dir;
}

test("a scoring failure withholds the item in block mode and is logged without the text", async () => {
  const r = await run(["--detect-injection=block", "--injection-model", brokenAtRunTime()], [call(1, "single"), call(2, "clean")]);
  assert.equal(r.messages[0].result.content[0].text, ERROR_NOTICE);
  assert.equal(r.messages[1].result.content[0].text, ERROR_NOTICE);
  const errors = r.audit.filter((e) => e.event === "injection-error");
  assert.equal(errors.length, 2);
  assert.deepEqual([errors[0].tool, errors[0].path, errors[0].action], ["single", "result.content[0].text", "block"]);
  assert.equal(typeof errors[0].error, "string");
  assert.match(r.stderr, /tools\/call \(single\): could not check result\.content\[0\]\.text for prompt injection .* — withheld/);
  assert.doesNotMatch(r.stderr + JSON.stringify(r.audit), SECRET_PHRASE);
});

test("a scoring failure in report mode forwards the result", async () => {
  const r = await run(["--detect-injection=report", "--injection-model", brokenAtRunTime()], [call(1, "single")]);
  assert.match(r.messages[0].result.content[0].text, SECRET_PHRASE);
  assert.equal(r.audit.filter((e) => e.event === "injection-error")[0].action, "report");
});

test("a scoring failure under --dry-run changes nothing", async () => {
  const r = await run(["--detect-injection=block", "--dry-run", "--injection-model", brokenAtRunTime()], [call(1, "single")]);
  assert.match(r.messages[0].result.content[0].text, SECRET_PHRASE);
});

test("start-up fails with the install command when the optional packages are missing", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-nopeers-"));
  fs.cpSync(path.join(ROOT_DIR, "dist"), path.join(dir, "dist"), { recursive: true });
  fs.cpSync(path.join(ROOT_DIR, "models"), path.join(dir, "models"), { recursive: true });
  fs.copyFileSync(path.join(ROOT_DIR, "package.json"), path.join(dir, "package.json"));
  const r = await run(["--detect-injection", "--injection-model", TINY], [call(1, "single")], path.join(dir, "dist/cli.js"));
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /npm install onnxruntime-node @huggingface\/tokenizers/);
  assert.equal(r.messages.length, 0);
});

test("start-up fails on a model directory that does not exist", async () => {
  const r = await run(["--detect-injection", "--injection-model", path.join(os.tmpdir(), "mcpg-missing-model")], []);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /mcp-guardrail: injection model/);
});

test("scan rejects --injection-model", async () => {
  const p = spawn(process.execPath, [CLI, "scan", "--injection", "--injection-model", TINY, "-"], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  p.stderr.on("data", (d: Buffer) => (stderr += d));
  p.stdin.end("hello");
  const code = await new Promise((r) => p.on("close", r));
  assert.equal(code, 2);
  assert.match(stderr, /scan uses the built-in model/);
});
