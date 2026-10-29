// Every rule must run in (near) linear time on adversarial input. A
// super-linear rule lets anyone who controls content an MCP server returns
// (a web page, an issue comment, a file) freeze the proxy and the session.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_RULES, Sanitizer } from "../src/index.js";

// Repeated units built from prefixes and separators the rules care about.
const UNITS = [
  "a", " ", "\t", "\n", "@", "=", ":", ".", "-", "_", "/", "\"", "'",
  "a.", "a@", "a@a.", "a-", "1 ", "1-", "1.", "1", "ab:", "a:", "::", "a=", "aa:",
  "password=", "DB_PASSWORD", "_password", "password", "aws", "awskey=", "aws_secret_",
  "-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n-----END", "PRIVATE KEY",
  "Bearer ", "Bearer a", "Basic ", "://", "a://", "x://a:", "x://a:b", "eyJ", "eyJaaaaaaaa.",
  "+1 ", "+44 ", "(512) ", "512-", "sk-", "sk-ant-", "ghp_", "AIza", "xoxb-", "github_pat_",
  "token: ", "secret_key: \"", "1.1.1.", "fe80:", "0:0:", "A::B ",
];

const SIZE = 150_000;
const BUDGET_MS = 400; // generous for slow CI runners; linear rules take < 20 ms

for (const rule of DEFAULT_RULES) {
  test(`linear time: ${rule.id}`, () => {
    const s = new Sanitizer({ rules: [rule] });
    let worst = { unit: "", ms: 0 };
    for (const unit of UNITS) {
      const input = unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);
      const t0 = performance.now();
      s.sanitizeString(input);
      const ms = performance.now() - t0;
      if (ms > worst.ms) worst = { unit, ms };
    }
    assert.ok(
      worst.ms < BUDGET_MS,
      `${rule.id} took ${worst.ms.toFixed(0)} ms on ${SIZE / 1000} KB of ${JSON.stringify(worst.unit)}`,
    );
  });
}

test("linear scaling: 4x the input costs < 8x the time (quadratic would be ~16x)", () => {
  const s = new Sanitizer();
  for (const unit of ["a.", "a@", "1 ", "ab:", "password=", "-----BEGIN PRIVATE KEY-----"]) {
    const time = (n: number) => {
      const input = unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
      const t0 = performance.now();
      s.sanitizeString(input);
      return performance.now() - t0;
    };
    time(50_000); // warm up
    const small = Math.max(time(100_000), 1);
    const big = time(400_000);
    assert.ok(big / small < 8 || big < 50, `${JSON.stringify(unit)}: 100KB ${small.toFixed(1)} ms, 400KB ${big.toFixed(1)} ms`);
  }
});
