import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = path.join(ROOT, "scripts/check-release.mjs");
const check = (cwd: string, ...args: string[]) =>
  spawnSync(process.execPath, [SCRIPT, ...args], { cwd, encoding: "utf8" });

function copyRepo(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-release-"));
  for (const f of ["package.json", "README.md"]) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  for (const d of ["models", "docs/benchmarks"]) fs.cpSync(path.join(ROOT, d), path.join(dir, d), { recursive: true });
  return dir;
}

test("release checks pass on the repository", () => {
  const r = check(ROOT);
  assert.equal(r.status, 0, r.stderr + r.stdout);
});

test("release checks fail when the README results table is edited by hand", () => {
  const dir = copyRepo();
  const readme = path.join(dir, "README.md");
  const text = fs.readFileSync(readme, "utf8");
  const edited = text.replace(/(<!-- results:start -->[\s\S]*?)(\d+\.\d)%/, "$199.9%");
  assert.notEqual(edited, text);
  fs.writeFileSync(readme, edited);
  const r = check(dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /README results table/);
  assert.equal(check(dir, "--write").status, 0);
  assert.equal(fs.readFileSync(readme, "utf8"), text);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("release checks fail when a runtime dependency is added", () => {
  const dir = copyRepo();
  const p = path.join(dir, "package.json");
  fs.writeFileSync(p, JSON.stringify({ ...JSON.parse(fs.readFileSync(p, "utf8")), dependencies: { leftpad: "1.0.0" } }));
  const r = check(dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /runtime dependenc/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("release checks fail when the weights file reaches 500 KB", () => {
  const dir = copyRepo();
  fs.writeFileSync(path.join(dir, "models/injection-linear-v1.bin"), Buffer.alloc(500 * 1024));
  const r = check(dir);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /500 KB/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("release checks fail when the README results block is empty or missing", () => {
  for (const mutate of [
    (t: string) => t.replace(/<!-- results:start -->[\s\S]*?<!-- results:end -->/, "<!-- results:start -->\n<!-- results:end -->"),
    (t: string) => t.replace(/<!-- results:start -->[\s\S]*?<!-- results:end -->/, ""),
  ]) {
    const dir = copyRepo();
    const readme = path.join(dir, "README.md");
    const text = fs.readFileSync(readme, "utf8");
    const edited = mutate(text);
    assert.notEqual(edited, text);
    fs.writeFileSync(readme, edited);
    const r = check(dir);
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, /README results table/);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("encoder and Prompt Guard figures join the README table once they exist", () => {
  const dir = copyRepo();
  const resultsPath = path.join(dir, "docs/benchmarks/results.json");
  const results = JSON.parse(fs.readFileSync(resultsPath, "utf8"));
  for (const p of results.protocols) {
    if (p.name.startsWith("lodo/")) {
      p.encoder = { tpr_fpr1: 0.912, tpr_fpr01: 0.8, auroc: 0.99, base_model: "x", scored_with: "y" };
      p.promptguard = { tpr_fpr1: 0.205, tpr_fpr01: 0.1, auroc: 0.7, model: "z" };
    }
  }
  fs.writeFileSync(resultsPath, JSON.stringify(results));
  assert.equal(check(dir).status, 1, "stale table must fail");
  assert.equal(check(dir, "--write").status, 0);
  assert.equal(check(dir).status, 0);
  const readme = fs.readFileSync(path.join(dir, "README.md"), "utf8");
  assert.match(readme, /\| Transformer \(optional\) at 1% \| Prompt Guard 2 at 1% \|/);
  assert.match(readme, /\| 91\.2% \| 20\.5% \|/);
  fs.rmSync(dir, { recursive: true, force: true });
});
