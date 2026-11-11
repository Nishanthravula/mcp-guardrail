# Injection detection for tool results — design

Date: 2026-11-11 · Status: awaiting review · Target release: 0.3.0

## 1. Goal

mcp-guardrail today stops secrets and PII leaving a tool result. This adds the
opposite direction of risk: text inside a tool result that tries to give the
model instructions (indirect prompt injection). The proxy scores every tool
result and reports or blocks the ones that look like an injection.

Success means three things:

1. A user turns it on with one flag and it works with no extra install.
2. Every published number can be regenerated with one command.
3. The documentation states where the detector fails.

## 2. What was said, and what is assumed

Said by the maintainer: build the injection detector first; ship it with
documentation, end-to-end and unit tests, and evidence for the claims; it is a
portfolio project for ML / LLM / AI engineer roles.

Assumed (correct these in review):

- It ships inside this package, not as a separate one.
- The package keeps its "zero-dependency" promise for anyone who does not opt
  in to the larger model.
- Detection is off by default in 0.3.0, because a false positive that blocks a
  legitimate tool result is worse for trust than a missed attack that would
  also have been missed yesterday.

## 3. Constraints found during exploration

| Constraint | Consequence |
|---|---|
| The package advertises zero runtime dependencies | The default detector must run in plain TypeScript with no native module |
| The build workspace cannot reach Hugging Face and has no GPU (2 CPUs, 7 GB) | A transformer cannot be downloaded or fine-tuned here; that part runs on the maintainer's machine or Colab |
| GitHub and PyPI are reachable from the build workspace | Datasets hosted on GitHub and a scikit-learn model can be built and tested here |
| Existing tests cover unit, regression, ReDoS and end-to-end against a real MCP server, on Node 18–24 | New code follows the same layout and must pass the same matrix |

## 4. Approach: two tiers, built in two phases

**Tier 1 — built-in linear model (phase 1, this spec's build scope).**
A logistic regression over hashed character and word n-grams. Weights ship in
the npm package as one file; inference is a pure TypeScript dot product. No
dependency, sub-millisecond per result.

**Tier 2 — optional encoder model (phase 2, specced here, built after phase 1).**
A fine-tuned small transformer exported to ONNX. It loads only when the user
installs `onnxruntime-node` and points the config at a model file. If the
runtime is missing, startup fails with an install hint; it never falls back
silently.

Why two tiers rather than only the encoder: the encoder breaks the
zero-dependency promise and cannot be trained in the build workspace. The
linear model gives a complete, shippable, benchmarked feature now, and becomes
the baseline the encoder has to beat.

Expected outcome, stated up front: the linear model will probably be clearly
weaker than published encoder detectors on attacks unlike its training data.
The benchmark reports that as measured. Phase 1 does not claim state of the art.

## 5. Components

Each unit has one job and can be tested alone.

### TypeScript (shipped)

| File | Job | Depends on |
|---|---|---|
| `src/injection/normalize.ts` | Canonicalise text before scoring: Unicode NFKC, strip zero-width characters, lower-case, collapse whitespace | nothing |
| `src/injection/featurize.ts` | Turn normalised text into hashed n-gram counts (fixed hash, fixed feature count) | normalize |
| `src/injection/linear.ts` | Load the weights file, check its format version and checksum, compute a probability | featurize |
| `src/injection/detector.ts` | Public `InjectionDetector`: split long text into overlapping windows, score each, return the maximum score and the offset of the highest-scoring window | linear |
| `src/proxy.ts` (edit) | After redaction, score each text item of a tool result; report or block per config | detector |
| `src/config.ts`, `guardrail.schema.json` (edit) | New `injection` section and per-tool override, with the existing strict validation | — |
| `src/audit.ts` (edit) | New `injection` / `would-injection` events | — |
| `src/cli.ts`, `src/scan.ts` (edit) | `--detect-injection[=report\|block]`, `--injection-threshold`, and `scan --injection` | detector |
| `models/injection-linear-v1.bin` + `.json` | Weights (int8-quantised) and metadata: feature count, hash seed, threshold table, training commit | — |

Size budget for the weights file: under 500 KB.

### Python (not shipped to npm; lives in `ml/`)

| File | Job |
|---|---|
| `ml/data/sources.py` | Download each dataset from its upstream at a pinned commit, verify a checksum, convert to one schema: `text, label, source, attack_family` |
| `ml/features.py` | The same normalise and featurise logic as the TypeScript side |
| `ml/train.py` | Train the linear model with a fixed seed; write weights and metadata |
| `ml/evaluate.py` | Run the evaluation protocol in section 7 and write `docs/benchmarks/RESULTS.md` and `results.json` |
| `ml/export_golden.py` | Write golden vectors (input text, expected features, expected score) used by the TypeScript parity test |
| `ml/tests/` | pytest suite |

Datasets are downloaded by script, never committed. Each dataset's licence is
checked before it is added, and recorded in `ml/data/README.md`.

## 6. Behaviour in the proxy

Config:

```jsonc
{
  "injection": {
    "mode": "off",          // "off" | "report" | "block"
    "threshold": 0.9,        // optional; if omitted, the model metadata's 1%-false-positive threshold is used
    "model": "builtin"       // phase 2 adds a path to an ONNX file
  },
  "tools": {
    "read_text_file": { "injection": "block" },
    "list_directory": { "injection": "off" }
  }
}
```

- **Order:** redaction runs first, then injection scoring on the redacted
  text, so the detector never sees a secret.
- **report:** the result is forwarded unchanged; stderr and the audit log get
  the tool name, JSON path, score and model version.
- **block:** the flagged text item is replaced with a fixed notice:
  `[mcp-guardrail: withheld — this tool result looks like a prompt injection (score 0.97). Run with --dry-run to inspect.]`
  Other items in the same result are kept. The JSON-RPC envelope is untouched.
- **--dry-run:** nothing is replaced; events are logged as `would-injection`.
- **Never logged:** the flagged text itself, consistent with the existing rule
  that logs contain no values.
- **Per-tool `skip`:** already bypasses everything; it bypasses this too.
- **Only tool results are scored** (`tools/call` responses and
  `structuredContent` strings). Requests and tool descriptions are out of scope.

Error handling:

- Weights file missing, wrong format version or bad checksum: startup fails
  with a clear message. A security feature must not run half-configured.
- Unknown config key or mode: rejected by the existing strict validation.
- Input longer than a cap (default 1 MB per text item): the first and last
  512 KB are scored and the audit event records `truncated: true`.
- Scoring cost is linear in input length; a test enforces it.

## 7. Evidence: how the numbers are produced

All results come from `python -m ml.evaluate`, which writes the results file.
No number in the README is typed by hand; a CI check fails if the README table
differs from `results.json`.

- **Data.** Attack sets that embed injections in tool outputs, plus benign
  tool outputs. Candidates: InjecAgent and AgentDojo (GitHub-hosted, reachable
  from the build workspace) and benign results captured from real MCP servers
  run over open-source repositories. Sets hosted only on Hugging Face are added
  in phase 2. The final list is fixed in the implementation plan after licence
  checks.
- **Protocol.** Leave-one-dataset-out: train on all sources but one, test on
  the held-out one, repeat. This measures attacks unlike the training data,
  which a random split hides.
- **Metrics.** Detection rate at 1% and at 0.1% false positives, AUROC, and
  latency per kilobyte on one CPU core.
- **Baselines.** A keyword/regex rule list and the linear model in phase 1.
  Phase 2 adds the fine-tuned encoder and Meta Prompt Guard 2.
- **Reproducibility.** Pinned dataset commits and checksums, fixed seeds,
  pinned Python dependencies, and the git commit recorded in the results file.
- **Limitations page.** `docs/injection-detection.md` lists measured weak
  spots (for example a held-out source with low detection) next to the wins.

## 8. Tests

| Level | What it proves |
|---|---|
| Unit (TS) | Normalisation cases (zero-width characters, compatibility forms such as full-width letters via NFKC, mixed case); feature hashing is stable across Node 18–24; weights loader rejects bad version and checksum; windowing finds an injection buried in the middle of a long benign text |
| Parity (TS vs Python) | Golden vectors: the TypeScript score equals the Python score within 1e-6 on at least 500 texts, including non-ASCII |
| Regression | A fixed set of known attacks must score above threshold and a fixed set of tricky benign texts (security documentation, a README that discusses prompt injection) must score below |
| Performance | 1 MB input scores in linear time under a fixed budget, in the style of the existing ReDoS tests |
| Config | New keys validated; typos get "did you mean" suggestions |
| End-to-end | Fake MCP server returns a clean result and an injected one through the real proxy: report mode forwards both and logs one event; block mode replaces only the injected item; dry-run changes nothing; audit log contains no result text; redaction still works in the same message |
| Python | Dataset converters, deterministic training (same seed gives identical weights), metric functions against hand-computed cases |

CI gains a Python job (tests plus regenerating the golden vectors and checking
they match the committed ones). The Node matrix is unchanged.

## 9. Documentation

- README: a short "Detect prompt injection in tool results" section with the
  one-flag quick start and the results table.
- `docs/injection-detection.md`: how it works, configuration, how to choose a
  threshold, limitations.
- `MODEL_CARD.md`: training data and licences, intended use, metrics, known
  failure cases, how to retrain.
- `docs/benchmarks/RESULTS.md`: generated.
- `CHANGELOG.md` entry for 0.3.0 and a schema update.

## 10. Phase 2 (after phase 1 ships)

1. Fine-tune a small encoder on the same data plus Hugging Face-hosted sets;
   run on the maintainer's Mac or Colab using `ml/train_encoder.py`.
2. Export to ONNX, quantise, load through optional `onnxruntime-node`.
3. Add it and Prompt Guard 2 to the benchmark table.
4. Agent test: run an agent on the AgentDojo attack suite with the proxy off
   and on; report attack success rate and task completion. Needs an LLM API
   key and a small budget from the maintainer.
5. Publish the model and model card on Hugging Face; live demo page.

## 11. Out of scope

Tool-description poisoning, non-English attacks (measured if a dataset has
them, not targeted), a hosted API, rewriting or "cleaning" flagged text, and
scoring requests sent to the server.

## 12. Risks

| Risk | Handling |
|---|---|
| Linear model is weak on held-out attacks | Report it; default mode stays `off`; the encoder is phase 2 |
| False positives on documents that discuss prompt injection | Regression set of such texts; threshold chosen at a fixed false-positive rate, not by accuracy |
| Python and TypeScript featurisers drift apart | Parity test on golden vectors in CI |
| A dataset licence forbids redistribution | Scripts download from upstream; nothing is committed; an unclear licence means the set is excluded |
| Look-alike letters from other scripts (for example Cyrillic) are not folded by NFKC | Listed as a known limitation; measured in the regression set, not fixed in phase 1 |
| Benign data is too unlike real tool traffic | Capture benign results from real MCP servers rather than relying on chat datasets |
