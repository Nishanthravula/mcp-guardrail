// Transport faults a real server can't trigger on demand, driven through the
// built CLI with raw stdio against a scripted fake server.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { CLI, FAKE_SERVER } from "./helpers.js";

interface Run { code: number | null; stdout: string; stderr: string; timedOut: boolean; ms: number }

function run(serverArgs: string[], opts: { stdin?: string[]; closeStdin?: boolean; timeoutMs?: number; cmd?: string; flags?: string[] } = {}): Promise<Run> {
  const { stdin = [], closeStdin = true, timeoutMs = 10_000, cmd = process.execPath, flags = [] } = opts;
  return new Promise((resolve) => {
    const t0 = performance.now();
    const p = spawn(process.execPath, [CLI, ...flags, "--", cmd, ...serverArgs], { stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    let err = "";
    let timedOut = false;
    p.stdout.on("data", (d: Buffer) => out.push(d));
    p.stderr.on("data", (d: Buffer) => (err += d));
    for (const l of stdin) p.stdin.write(l + "\n");
    if (closeStdin) p.stdin.end();
    const timer = setTimeout(() => { timedOut = true; p.kill("SIGKILL"); }, timeoutMs);
    p.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: Buffer.concat(out).toString("utf8"), stderr: err, timedOut, ms: performance.now() - t0 });
    });
  });
}

test("UTF-8 split into 1-byte chunks arrives intact", async () => {
  const r = await run([FAKE_SERVER, "utf8-split"]);
  assert.equal(JSON.parse(r.stdout).result.text, "café — 日本語 — 🚀 — naïve résumé");
});

test("10 MB final response: complete, redacted, and fast", async () => {
  const r = await run([FAKE_SERVER, "big", "10"], { timeoutMs: 60_000 });
  const m = JSON.parse(r.stdout);
  assert.ok(m.result.text.endsWith("[REDACTED:AWS_ACCESS_KEY_ID]"));
  assert.ok(r.ms < 15_000, `${r.ms.toFixed(0)} ms`);
});

test("final response is delivered when the server exits immediately (20 runs)", async () => {
  for (let i = 0; i < 20; i++) {
    const r = await run([FAKE_SERVER, "exit-fast"]);
    assert.match(r.stdout, /\[REDACTED:AWS_ACCESS_KEY_ID\]/);
  }
});

test("final message without a trailing newline is delivered", async () => {
  const r = await run([FAKE_SERVER, "no-newline"]);
  assert.equal(JSON.parse(r.stdout).result.text, "no trailing newline");
});

test("server crash: earlier output delivered, exit code propagated", async () => {
  const r = await run([FAKE_SERVER, "crash"]);
  assert.equal(r.code, 3);
  assert.match(r.stdout, /before crash/);
});

test("missing server command: clean message, exit 127, no stack trace", async () => {
  const r = await run(["--version"], { cmd: "mcp-server-that-does-not-exist" });
  assert.equal(r.code, 127);
  assert.match(r.stderr, /could not start "mcp-server-that-does-not-exist"/);
  assert.doesNotMatch(r.stderr, /\n\s+at /);
});

test("client closes stdin: server sees EOF and everything exits", async () => {
  const r = await run([FAKE_SERVER, "echo"], {
    stdin: [JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping", params: { a: 1 } })],
    timeoutMs: 4000,
  });
  assert.equal(r.timedOut, false);
  assert.equal(r.code, 0);
  assert.deepEqual(JSON.parse(r.stdout.trim()).result.got, { a: 1 });
});

test("non-JSON stdout lines are redacted too", async () => {
  const r = await run([FAKE_SERVER, "log-noise"]);
  assert.match(r.stdout.split("\n")[0], /^Server starting with key \[REDACTED:AWS_ACCESS_KEY_ID\]$/);
});

test("JSON-RPC ids are never rewritten", async () => {
  for (const id of ["1761660133733", "req-10.0.0.12-1", "4111111111111111", "a@b.co"]) {
    const r = await run([FAKE_SERVER, "string-id", id]);
    assert.equal(JSON.parse(r.stdout).id, id);
  }
});

test("structuredContent values under sensitive keys are redacted", async () => {
  const r = await run([FAKE_SERVER, "structured"]);
  const m = JSON.parse(r.stdout);
  assert.deepEqual(m.result.structuredContent, {
    user: "acme_admin",
    db_password: "[REDACTED:SECRET]",
    api_key: "[REDACTED:SECRET]",
  });
});

test("notifications keep their progressToken", async () => {
  const r = await run([FAKE_SERVER, "progress"]);
  const m = JSON.parse(r.stdout);
  assert.equal(m.params.progressToken, "tok_8f3kQ9mZ2vL7xR4t");
});

test("blocked non-tool request gets a JSON-RPC error with its id", async () => {
  const r = await run([FAKE_SERVER, "echo"], {
    stdin: [JSON.stringify({ jsonrpc: "2.0", id: 7, method: "resources/write", params: { text: "[REDACTED:SECRET]" } })],
  });
  const m = JSON.parse(r.stdout.trim());
  assert.equal(m.id, 7);
  assert.equal(m.error.code, -32602);
});
