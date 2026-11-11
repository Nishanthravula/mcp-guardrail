// v0.2 features end to end: the built CLI, a real MCP client and the official
// filesystem server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { S, CLI, makeFixture, connect, text } from "./helpers.js";

let root: string;
const ACME = "acme_" + "Q7mR2vL9tW4nB8cF3hJ6sD1gY5zAxK0p";
const cfgPath = () => path.join(root, "guardrail.json");
const auditPath = () => path.join(root, "audit", "guardrail.jsonl");
const read = (c: Client, rel: string) => c.callTool({ name: "read_text_file", arguments: { path: path.join(root, rel) } });
const auditEvents = () => fs.readFileSync(auditPath(), "utf8").trim().split("\n").map((l) => JSON.parse(l));

before(() => {
  root = makeFixture();
  fs.writeFileSync(path.join(root, "acme.txt"), `internal key ${ACME}\ncontact support@acme.io or jane@gmail.com\n`);
  fs.writeFileSync(
    cfgPath(),
    JSON.stringify({
      allow: ["support@acme.io"],
      rules: [{ id: "acme-key", pattern: "acme_[A-Za-z0-9]{32}", label: "ACME_KEY" }],
      tools: {
        list_directory: { skip: true },
        read_multiple_files: { disable: ["email"] },
      },
      auditLog: "audit/guardrail.jsonl",
    }),
  );
});
after(() => fs.rmSync(root, { recursive: true, force: true }));

test("config: custom rule, allowlist and audit log are applied", async () => {
  const c = await connect(root, ["--config", cfgPath()]);
  try {
    const out = text(await read(c, "acme.txt"));
    assert.equal(out, "internal key [REDACTED:ACME_KEY]\ncontact support@acme.io or [REDACTED:EMAIL]\n");
  } finally {
    await c.close();
  }
});

test("per-tool policies: skip one tool, relax a rule for another, default elsewhere", async () => {
  fs.mkdirSync(path.join(root, "people/jane@gmail.com"), { recursive: true });
  const c = await connect(root, ["--config", cfgPath()]);
  try {
    // list_directory is skipped: the folder name stays usable
    const listing = text(await c.callTool({ name: "list_directory", arguments: { path: path.join(root, "people") } }));
    assert.match(listing, /jane@gmail\.com/);
    // read_multiple_files has "email" disabled, but secrets are still redacted
    const multi = text(await c.callTool({ name: "read_multiple_files", arguments: { paths: [path.join(root, "acme.txt")] } }));
    assert.match(multi, /jane@gmail\.com/);
    assert.match(multi, /\[REDACTED:ACME_KEY\]/);
    // read_text_file has no policy: email redacted as usual
    assert.match(text(await read(c, "acme.txt")), /\[REDACTED:EMAIL\]/);
  } finally {
    await c.close();
  }
});

test("audit log: start/redact/block/stop events, tool names, paths, never values", async () => {
  fs.rmSync(auditPath(), { force: true });
  const c = await connect(root, ["--config", cfgPath()]);
  try {
    await read(c, ".env");
    await read(c, ".env");
    const seen = text(await read(c, ".env"));
    await c.callTool({ name: "write_file", arguments: { path: path.join(root, ".env"), content: seen } });
  } finally {
    await c.close();
  }
  await new Promise((r) => setTimeout(r, 300)); // let the proxy write "stop"
  const raw = fs.readFileSync(auditPath(), "utf8");
  for (const v of Object.values(S)) assert.ok(!raw.includes(v), "audit log contains a secret value");
  assert.equal((fs.statSync(auditPath()).mode & 0o777).toString(8), "600");

  const ev = auditEvents();
  assert.equal(ev[0].event, "start");
  assert.equal(ev.at(-1).event, "stop");
  const reds = ev.filter((e) => e.event === "redact" && e.tool === "read_text_file");
  assert.equal(reds.length, 3);
  // The filesystem server returns the file twice: in content and structuredContent.
  assert.equal(reds[0].redactions.AWS_ACCESS_KEY_ID, 2);
  const awsDetails = reds[0].details.filter((d: { rule: string }) => d.rule === "aws-access-key-id");
  assert.deepEqual(awsDetails.map((d: { path: string }) => d.path), ["result.content[0].text", "result.structuredContent.content"]);
  const awsDetail = awsDetails[0];
  assert.equal(awsDetails[1].fp, awsDetail.fp);
  assert.match(awsDetail.fp, /^[0-9a-f]{16}$/);
  // same secret, same session -> same fingerprint
  const fp2 = reds[1].details.find((d: { rule: string }) => d.rule === "aws-access-key-id").fp;
  assert.equal(fp2, awsDetail.fp);
  const block = ev.find((e) => e.event === "block");
  assert.deepEqual([block.tool, block.reason, block.method], ["write_file", "placeholder", "tools/call"]);
});

test("--dry-run: traffic is untouched, findings are logged as would-*", async () => {
  const audit = path.join(root, "audit", "dry.jsonl");
  const raw = await connect(root, [], false);
  const dry = await connect(root, ["--dry-run", "--audit-log", audit]);
  try {
    assert.equal(text(await read(dry, ".env")), text(await read(raw, ".env")));
    // a write that would be blocked goes through in dry-run
    const target = path.join(root, "copy.env");
    fs.writeFileSync(target, "x");
    const r = await dry.callTool({ name: "write_file", arguments: { path: target, content: "A=[REDACTED:SECRET]" } });
    assert.ok(!r.isError, text(r));
    assert.equal(fs.readFileSync(target, "utf8"), "A=[REDACTED:SECRET]");
  } finally {
    await raw.close();
    await dry.close();
  }
  await new Promise((r) => setTimeout(r, 300));
  const ev = fs.readFileSync(audit, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(ev[0].dryRun, true);
  assert.ok(ev.some((e) => e.event === "would-redact" && e.tool === "read_text_file" && e.redactions.AWS_ACCESS_KEY_ID === 2));
  assert.ok(ev.some((e) => e.event === "would-block" && e.reason === "placeholder"));
  assert.ok(!ev.some((e) => e.event === "redact" || e.event === "block"));
});

// ---------------------------------------------------------------- subcommands

const cli = (...args: string[]) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });

test("scan: finds secrets, exits 1, never prints a value; --json parses", () => {
  const r = cli("scan", "--no-color", "--config", cfgPath(), root);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /\.env:2:19 {2}AWS_ACCESS_KEY_ID/);
  assert.match(r.stdout, /acme\.txt:1:14 {2}ACME_KEY/);
  // jane@gmail.com (column 28) is reported; allowlisted support@acme.io (column 9) is not
  assert.match(r.stdout, /acme\.txt:2:28 {2}EMAIL {2}email\n {4}contact support@acme\.io or \[EMAIL\]/);
  assert.doesNotMatch(r.stdout, /acme\.txt:2:9 /);
  for (const v of [...Object.values(S), ACME]) assert.ok(!r.stdout.includes(v), "scan printed a secret");

  const j = cli("scan", "--json", path.join(root, "src"));
  assert.equal(j.status, 0, j.stderr);
  assert.deepEqual(JSON.parse(j.stdout).findings, []);
});

test("check-config: OK summary; typos and slow regexes exit 2 with a clear message", () => {
  const ok = cli("check-config", cfgPath());
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /OK\n {2}active rules: \d+ \(1 custom\)/);
  assert.match(ok.stdout, /tool policies: list_directory, read_multiple_files/);

  const bad = path.join(root, "bad.json");
  fs.writeFileSync(bad, JSON.stringify({ disable: ["emial"] }));
  const typo = cli("check-config", bad);
  assert.equal(typo.status, 2);
  assert.match(typo.stderr, /unknown rule id "emial" \(did you mean "email"\?\)/);

  fs.writeFileSync(bad, JSON.stringify({ rules: [{ id: "evil", pattern: "(a+)+$" }] }));
  const slow = cli("check-config", bad);
  assert.equal(slow.status, 2);
  assert.match(slow.stderr, /too slow.*\n {2}- evil: did not finish/);
});

test("proxy refuses a bad config before starting the server", () => {
  const bad = path.join(root, "bad2.json");
  fs.writeFileSync(bad, JSON.stringify({ quite: true }));
  const r = cli("--config", bad, "--", process.execPath, "-e", "setTimeout(()=>{}, 60000)");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown key "quite" \(did you mean "quiet"\?\)/);
});

test("--version and MCP_GUARDRAIL_CONFIG", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(CLI, "../../package.json"), "utf8"));
  assert.equal(cli("--version").stdout.trim(), pkg.version);
  const r = spawnSync(process.execPath, [CLI, "scan", "--no-color", path.join(root, "acme.txt")], {
    encoding: "utf8",
    env: { ...process.env, MCP_GUARDRAIL_CONFIG: cfgPath() },
  });
  assert.match(r.stdout, /ACME_KEY/);
});
