#!/usr/bin/env node
// Release checks that keep published claims tied to generated evidence.
//
//   node scripts/check-release.mjs           verify (exit 1 on any failure)
//   node scripts/check-release.mjs --write   rewrite the generated blocks in the docs
//
// Checks: no runtime dependencies; weights file under 500 KB; every
// <!-- results:start/end --> and <!-- model:start/end --> block in the docs
// equals the text generated from docs/benchmarks/results.json and the model
// metadata, so no benchmark number is ever typed by hand.
import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const write = process.argv.includes("--write");
const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
const MODEL = "models/injection-linear-v1";
const MAX_WEIGHT_BYTES = 500 * 1024;
const DOCS = ["README.md", "docs/injection-detection.md", "MODEL_CARD.md"];
const NAMES = { "lodo/injecagent": "InjecAgent", "lodo/agentdojo": "AgentDojo" };
const pct = (x) => `${(x * 100).toFixed(1)}%`;

const errors = [];

const pkg = JSON.parse(read("package.json"));
if (pkg.dependencies && Object.keys(pkg.dependencies).length > 0) {
  errors.push(`package.json declares runtime dependencies: ${Object.keys(pkg.dependencies).join(", ")}`);
}

const weightBytes = fs.statSync(path.join(root, `${MODEL}.bin`)).size;
if (weightBytes >= MAX_WEIGHT_BYTES) {
  errors.push(`${MODEL}.bin is ${weightBytes} bytes; it must stay under 500 KB`);
}

const results = JSON.parse(read("docs/benchmarks/results.json"));
const meta = JSON.parse(read(`${MODEL}.json`));

const blocks = {
  results: [
    "| Dataset never seen in training | Attacks | Benign | Detected at 1% false positives | Detected at 0.1% | Keyword rules detect |",
    "|---|---|---|---|---|---|",
    ...results.protocols
      .filter((p) => p.name in NAMES)
      .map(
        (p) =>
          `| ${NAMES[p.name]} | ${p.test_pos.toLocaleString("en-US")} | ${p.test_neg.toLocaleString("en-US")} ` +
          `| ${pct(p.linear.tpr_fpr1)} | ${pct(p.linear.tpr_fpr01)} | ${pct(p.regex.tpr)} |`,
      ),
  ].join("\n"),
  model: [
    `- Default threshold: ${meta.thresholds.default}`,
    `- Grouped ${meta.cv.folds}-fold cross-validation at that threshold: ${pct(meta.cv.detected_at_default)} of ` +
      `${meta.cv.attacks.toLocaleString("en-US")} attacks detected, ${(meta.cv.false_positives_at_default * 100).toFixed(2)}% of ` +
      `${meta.cv.benign.toLocaleString("en-US")} benign results flagged (training-style data, including synthetic rows)`,
    `- Weights: ${weightBytes.toLocaleString("en-US")} bytes, SHA-256 \`${meta.sha256}\``,
  ].join("\n"),
};

// Which blocks each document must contain. A missing or empty block is an
// error: an unverified claim is worse than no claim.
const REQUIRED = {
  "README.md": ["results"],
  "docs/injection-detection.md": ["results", "model"],
  "MODEL_CARD.md": ["results", "model"],
};
const LABEL = { results: "README results table", model: "model facts" };
const stale = [];

for (const doc of DOCS) {
  if (!fs.existsSync(path.join(root, doc))) continue;
  let text = read(doc);
  for (const name of REQUIRED[doc]) {
    const start = `<!-- ${name}:start -->`;
    const end = `<!-- ${name}:end -->`;
    const from = text.indexOf(start);
    const to = text.indexOf(end);
    if (from < 0 || to < from) {
      errors.push(`${doc}: ${LABEL[name]} block (${start} … ${end}) is missing`);
      continue;
    }
    const expected = `${start}\n${blocks[name]}\n`;
    if (text.slice(from, to) !== expected) {
      stale.push(`${doc}: ${LABEL[name]} block differs from the generated values; run "npm run check:release -- --write"`);
      text = text.slice(0, from) + expected + text.slice(to);
    }
  }
  if (write) fs.writeFileSync(path.join(root, doc), text);
}
if (!write) errors.push(...stale);

if (errors.length) {
  for (const e of errors) process.stderr.write(`check-release: ${e}\n`);
  process.exit(1);
}
process.stdout.write(write ? "check-release: generated blocks written\n" : "check-release: OK\n");
