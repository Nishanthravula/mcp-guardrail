import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { EncoderDetector, InjectionDetector, loadScorer, tokenWindows } from "../src/index.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TINY = path.join(ROOT, "tests/fixtures/encoder-tiny");
const golden = JSON.parse(fs.readFileSync(path.join(TINY, "golden.json"), "utf8")) as {
  cases: { text: string; ids: number[]; score: number }[];
};
const MODEL_ERROR = { message: /^mcp-guardrail: injection model/ };

function copyTiny(mutate: (dir: string) => void): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcpg-enc-"));
  for (const f of fs.readdirSync(TINY)) fs.copyFileSync(path.join(TINY, f), path.join(dir, f));
  mutate(dir);
  return dir;
}

test("token windows match the Python reference", () => {
  assert.deepEqual(tokenWindows(0, 8, 3), []);
  assert.deepEqual(tokenWindows(5, 8, 3), [[0, 5]]);
  assert.deepEqual(tokenWindows(6, 8, 3), [[0, 6]]);
  assert.deepEqual(tokenWindows(10, 8, 3), [[0, 6], [3, 9], [4, 10]]);
  assert.deepEqual(tokenWindows(12, 8, 3), [[0, 6], [3, 9], [6, 12]]);
});

test("golden texts: token ids are identical and scores match Python within 1e-4", async () => {
  const d = await EncoderDetector.load(TINY);
  assert.ok(golden.cases.length >= 80);
  let worst = 0;
  for (const c of golden.cases) {
    assert.deepEqual(d.tokenIds(c.text), c.ids, JSON.stringify(c.text.slice(0, 40)));
    const r = await d.score(c.text);
    worst = Math.max(worst, Math.abs(r.score - c.score));
  }
  assert.ok(worst < 1e-4, `largest score difference ${worst}`);
  assert.ok(golden.cases.some((c) => c.ids.length > 126), "golden set includes multi-window texts");
});

test("metadata sets the name and default threshold; a custom threshold is validated", async () => {
  const d = await EncoderDetector.load(TINY);
  assert.equal(d.modelName, "encoder-tiny-test");
  assert.equal(d.threshold, 0.5);
  assert.equal((await EncoderDetector.load(TINY, { threshold: 0.9 })).threshold, 0.9);
  await assert.rejects(EncoderDetector.load(TINY, { threshold: 0 }), RangeError);
  await assert.rejects(EncoderDetector.load(TINY, { threshold: 1 }), RangeError);
});

test("empty and whitespace-only text score zero", async () => {
  const d = await EncoderDetector.load(TINY);
  assert.deepEqual(await d.score(""), { score: 0, flagged: false, windowStart: 0, truncated: false });
  assert.equal((await d.score(" \n\t ")).score, 0);
});

test("long items are capped like the built-in model", async () => {
  const d = await EncoderDetector.load(TINY);
  const r = await d.score("a b c d ".repeat(140_000));
  assert.equal(r.truncated, true);
  assert.ok(r.score >= 0 && r.score <= 1);
});

test("loading fails clearly on a broken model directory", async () => {
  await assert.rejects(EncoderDetector.load(path.join(os.tmpdir(), "mcpg-no-such-model")), MODEL_ERROR);
  await assert.rejects(EncoderDetector.load(copyTiny((d) => fs.rmSync(path.join(d, "tokenizer.json")))), MODEL_ERROR);
  await assert.rejects(
    EncoderDetector.load(
      copyTiny((d) => {
        const p = path.join(d, "model.onnx");
        const b = fs.readFileSync(p);
        b[b.length - 10] ^= 0xff;
        fs.writeFileSync(p, b);
      }),
    ),
    { message: /checksum/ },
  );
  for (const change of [{ format: 2 }, { kind: "linear" }, { maxLength: 2 }]) {
    await assert.rejects(
      EncoderDetector.load(
        copyTiny((d) => {
          const p = path.join(d, "guardrail.json");
          fs.writeFileSync(p, JSON.stringify({ ...JSON.parse(fs.readFileSync(p, "utf8")), ...change }));
        }),
      ),
      MODEL_ERROR,
      JSON.stringify(change),
    );
  }
});

test("loadScorer picks the built-in model unless a directory is given", async () => {
  assert.ok((await loadScorer(undefined)) instanceof InjectionDetector);
  assert.ok((await loadScorer("builtin", 0.7)) instanceof InjectionDetector);
  assert.equal((await loadScorer("builtin", 0.7)).threshold, 0.7);
  assert.ok((await loadScorer(TINY)) instanceof EncoderDetector);
});
