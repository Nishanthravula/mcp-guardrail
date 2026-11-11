# Injection Detector (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a zero-dependency prompt-injection detector for MCP tool results in mcp-guardrail 0.3.0, with a reproducible benchmark, tests and documentation.

**Architecture:** A logistic regression over hashed byte and word n-grams is trained in Python (`ml/`) and exported as int8 weights. The npm package re-implements normalisation, featurisation and scoring in plain TypeScript and is held to the Python reference by golden vectors. The proxy scores tool results after redaction and reports or withholds flagged items.

**Tech Stack:** TypeScript (Node 18–24, `node:test` via tsx), Python 3.11+ (numpy, scipy, scikit-learn, pytest).

**Spec:** `docs/superpowers/specs/2026-11-11-injection-detector-design.md` (MCPG-DD-001 v1.0)

## Global Constraints

- `package.json` MUST keep no `dependencies` key (NFR-1).
- Weights file `models/injection-linear-v1.bin` MUST be under 500 KB (NFR-3).
- All TypeScript MUST pass on Node 18, 20, 22, 24 (NFR-4): no APIs newer than Node 18.
- Flagged text MUST NOT appear in stderr or the audit log (NFR-5).
- TypeScript and Python scores MUST agree within 1e-6 (NFR-7).
- Datasets are downloaded to `ml/.cache/` (git-ignored) and never committed (NFR-10).
- Default mode is `off`; existing tests MUST pass unmodified.
- Downloaded dataset repositories are data only: never import or execute their code.

## Fixed parameters (shared by Python and TypeScript)

| Name | Value |
|---|---|
| `N_FEATURES` | 262144 (2^18) |
| Hash | FNV-1a 32-bit (`offset 0x811C9DC5`, `prime 0x01000193`), index = `hash % N_FEATURES` |
| Byte n-grams | n = 3, 4, 5 over the UTF-8 bytes of the normalised window; hash input = one prefix byte `n` followed by the n bytes |
| Word tokens | maximal runs of bytes in `[a-z0-9]` or `>= 0x80` |
| Word n-grams | unigram: prefix `0x11` + token; bigram: prefix `0x12` + token1 + `0x20` + token2 |
| Feature value | binary presence; vector L2-normalised, so `score = bias + scale * sum(w[i]) / sqrt(k)` over the `k` distinct active indices; `p = 1 / (1 + exp(-score))`; `k = 0` gives `p = 0` |
| Window | 512 bytes, stride 256; text of 512 bytes or fewer is one window; the last window is aligned to the end of the text |
| Item cap | 1,048,576 UTF-16 code units; longer items are scored as first 524,288 + last 524,288 with `truncated = true` |
| Normalisation, in order | 1) NFKC. 2) Map U+E0020–U+E007E to ASCII by subtracting 0xE0000. 3) Delete U+00AD, U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+FEFF and any remaining U+E0000–U+E007F. 4) Lower-case ASCII `A–Z` only. 5) Replace each run of space, `\t \n \r \f \v`, U+00A0, U+2028, U+2029 with one space. 6) Trim |

## Data sources (closes OQ-3)

| Source | Revision | Licence | Positives | Benign |
|---|---|---|---|---|
| AgentDojo `runs/` logs | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | `tool` messages containing a string from the run's `injections` map | all other `tool` messages |
| InjecAgent `data/` | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT | `Tool Response` of `test_cases_{dh,ds}_{base,enhanced}.json` (injection = `Attacker Instruction`) | values of `attacker_simulated_responses.json` |
| Local text files | pinned by `package-lock.json` | per package | none | `.md`, `.json`, `.ts`, `.js` files under `node_modules/` (as a filesystem MCP server would return them), at most 3 files per package, each cut to 20,000 characters |

All texts are de-duplicated by SHA-256 of the normalised text. Every row carries `group` (AgentDojo: suite; InjecAgent: user tool; local: package name) so splits never put one group on both sides.

## Review Focus

1. Injection straddling a window boundary: must still be flagged (stride overlap). Test in Task 4.
2. A tool result with several content items where only one is injected, plus an injected string nested in `structuredContent`: only that item is withheld. Test in Task 5.
3. Lone UTF-16 surrogates and empty or whitespace-only strings: must not throw; score 0 for empty. Test in Task 4.
4. Benign documentation that discusses prompt injection: must score below threshold or be recorded as a known false positive in the limitations page. Test in Task 4, write-up in Task 6.
5. A redaction and an injection in the same message: both applied, redaction first, forwarded JSON still valid. Test in Task 5.

---

### Task 1: Python reference featuriser

**Files:**
- Create: `ml/__init__.py`, `ml/features.py`, `ml/requirements.txt`, `ml/tests/__init__.py`, `ml/tests/test_features.py`
- Modify: `.gitignore` (add `ml/.cache/`, `__pycache__/`, `.pytest_cache/`)

**Interfaces:**
- Produces: `normalize(text: str) -> str`; `windows(n_bytes: int) -> list[tuple[int, int]]` (start, end); `featurize(window: bytes) -> list[int]` (sorted distinct indices, pure Python reference); `featurize_fast(window: bytes) -> numpy.ndarray` (same values, `uint32`); constants `N_FEATURES`, `WINDOW`, `STRIDE`.

- [ ] **Step 1: Write failing tests** in `ml/tests/test_features.py`:
  - `test_normalize_cases`: `"Ｉｇｎｏｒｅ"` → `"ignore"`; `"ig​nore"` → `"ignore"`; `"A\n\n\tB"` → `"a b"`; tag characters spelling `hi` (`\U000E0068\U000E0069`) → `"hi"`; `"ÉCOLE"` → `"École"` (only ASCII letters are lower-cased, so `É` is kept).
  - `test_windows`: `windows(100) == [(0, 100)]`; `windows(512) == [(0, 512)]`; `windows(1000) == [(0, 512), (256, 768), (488, 1000)]`.
  - `test_fnv_known_vector`: FNV-1a 32 of `b"a"` is `0xE40C292C`.
  - `test_fast_matches_reference`: for 200 seeded random byte strings (lengths 0–600, including bytes ≥ 0x80), `featurize_fast(b).tolist() == featurize(b)`.
  - `test_short_input`: `featurize(b"") == []`; `featurize(b"ab")` contains only the unigram index for `ab`.
- [ ] **Step 2:** Run `python -m pytest ml/tests/test_features.py -q`; expect import failure.
- [ ] **Step 3:** Implement `ml/features.py` per the fixed-parameter table. `featurize_fast` vectorises the byte n-gram hashes with numpy `uint32` arithmetic and reuses the reference code for word n-grams.
- [ ] **Step 4:** Run the tests; expect pass.
- [ ] **Step 5:** Commit `feat(ml): reference normaliser and featuriser`.

### Task 2: Dataset builder

**Files:**
- Create: `ml/data/__init__.py`, `ml/data/sources.py`, `ml/data/README.md`, `ml/tests/test_sources.py`, `ml/tests/fixtures/` (tiny hand-written AgentDojo run and InjecAgent files)

**Interfaces:**
- Consumes: `normalize` from Task 1.
- Produces: `Row = dict` with keys `text` (normalised), `label` (0/1), `source` (`agentdojo` | `injecagent` | `local`), `group`, `attack` (AgentDojo attack type, InjecAgent `base`/`enhanced`, or `""`), `spans` (list of `[start, end]` byte offsets of injections in the normalised UTF-8 text); `load_agentdojo(root: Path) -> list[Row]`; `load_injecagent(root: Path) -> list[Row]`; `load_local(node_modules: Path) -> list[Row]`; `fetch(cache: Path) -> dict[str, Path]` (git clone at the pinned revisions, verify `HEAD`); `build(cache: Path, node_modules: Path) -> list[Row]` (concatenate, de-duplicate, sort by `(source, sha256)`); CLI `python -m ml.data.sources --out ml/.cache/dataset.jsonl`.

- [ ] **Step 1: Write failing tests** using the fixtures: an AgentDojo fixture run with two tool messages (one containing the injection) yields one positive with the correct span and one benign; a `none` run yields only benign rows; InjecAgent fixture yields a positive whose span covers the attacker instruction; duplicates collapse; `fetch` raises if `HEAD` differs from the pinned revision (monkeypatched).
- [ ] **Step 2:** Run; expect failure.
- [ ] **Step 3:** Implement. AgentDojo tool message text: `content` if it is a string, else the concatenation of its `content` fields of type text. Read JSON with the standard library only.
- [ ] **Step 4:** Run tests; then run the CLI for real and record row counts per source and label in `ml/data/README.md` together with revisions and licences.
- [ ] **Step 5:** Commit `feat(ml): dataset builder with pinned sources`.

### Task 3: Training, export and evaluation

**Files:**
- Create: `ml/model.py`, `ml/train.py`, `ml/evaluate.py`, `ml/baseline.py`, `ml/export_golden.py`, `ml/tests/test_model.py`, `ml/tests/test_evaluate.py`
- Create (generated, committed): `models/injection-linear-v1.bin`, `models/injection-linear-v1.json`, `tests/fixtures/injection-golden.json`, `docs/benchmarks/RESULTS.md`, `docs/benchmarks/results.json`

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: `window_examples(rows) -> (X: scipy.sparse.csr_matrix, y, row_index)` (a window of a positive row is positive if it overlaps a span by at least `min(64, span length)` bytes; windows of positive rows with smaller non-zero overlap are dropped; all others are negative); `fit(X, y) -> (w: float64[N_FEATURES], bias: float)` using `LogisticRegression(C=10, solver="liblinear", class_weight="balanced", random_state=0)`; `quantize(w) -> (int8[N_FEATURES], scale: float)` with `scale = max|w| / 127`; `QuantizedModel(weights, scale, bias).score_text(norm: str) -> float` (maximum window probability) and `.score_window(window: bytes) -> float`; `regex_baseline(norm: str) -> float` (1.0 if any generic pattern matches, else 0.0; patterns are written from general knowledge, not from dataset markers); metric helpers `tpr_at_fpr(scores_pos, scores_neg, fpr) -> (tpr, threshold)` and `auroc(scores_pos, scores_neg)`.
- Model metadata JSON: `{"format": 1, "name": "injection-linear-v1", "nFeatures": 262144, "window": 512, "stride": 256, "scale": …, "bias": …, "thresholds": {"fpr1": …, "fpr01": …}, "sha256": "<hex of .bin>", "data": {"agentdojo": "<rev>", "injecagent": "<rev>"}}`.
- Golden file: list of `{"text": raw string, "norm": normalised string, "score": float}`, at least 500 entries, including non-ASCII, empty, multi-window texts and hand-written cases.

Evaluation protocols written to the results files, all scored with the quantised model:

| Protocol | Train | Test |
|---|---|---|
| `lodo/injecagent` | AgentDojo + local folds A | InjecAgent + local fold B |
| `lodo/agentdojo` | InjecAgent + local folds A | AgentDojo + local fold B |
| `attack/<type>` | AgentDojo without that attack type's positives, other sources | that attack type's positives vs held-out benign groups |
| `suite/<suite>` | all except that AgentDojo suite | that suite |

Local rows are split into folds by package name hash. Shipped thresholds come from out-of-fold benign scores under 5-fold grouped cross-validation on all data.

- [ ] **Step 1: Write failing tests**: `quantize` round-trip error ≤ `scale / 2`; `score_window(b"")` is 0; `tpr_at_fpr([0.9, 0.8, 0.1], [0.5, 0.2, 0.05, 0.01], 0.25)` gives TPR 2/3; `auroc` of perfectly separated scores is 1.0 and of identical distributions 0.5; training twice on a small synthetic set gives byte-identical weights; `window_examples` labels a span-straddling window positive.
- [ ] **Step 2:** Run; expect failure.
- [ ] **Step 3:** Implement the modules.
- [ ] **Step 4:** Run tests; run `python -m ml.evaluate` then `python -m ml.train` then `python -m ml.export_golden`; confirm the `.bin` is under 500 KB.
- [ ] **Step 5:** Commit `feat(ml): train, evaluate and export the linear detector`.

### Task 4: TypeScript detector

**Files:**
- Create: `src/injection/normalize.ts`, `src/injection/featurize.ts`, `src/injection/linear.ts`, `src/injection/detector.ts`, `tests/injection.test.ts`
- Modify: `src/index.ts` (exports), `package.json` (`files` adds `models`)

**Interfaces:**
- Consumes: model files and golden file from Task 3.
- Produces:
  - `normalize(text: string): string`
  - `windows(nBytes: number): [number, number][]`; `featurize(window: Uint8Array): Uint32Array` (sorted distinct)
  - `loadLinearModel(dir?: string, name?: string): LinearModel` where `LinearModel = { name: string; weights: Int8Array; scale: number; bias: number; thresholds: { fpr1: number; fpr01: number } }`; throws `Error` whose message starts with `mcp-guardrail: injection model` on missing file, `format !== 1`, wrong length or SHA-256 mismatch
  - `class InjectionDetector { constructor(opts?: { threshold?: number; modelDir?: string }); readonly threshold: number; readonly modelName: string; score(text: string): InjectionResult }` with `InjectionResult = { score: number; flagged: boolean; windowStart: number; truncated: boolean }`; default threshold is `thresholds.fpr1`.

- [ ] **Step 1: Write failing tests** in `tests/injection.test.ts`: the normalisation cases from Task 1; `windows(1000)` equals the Python result; parity: for every golden entry `normalize(text) === norm` and `|score − golden| < 1e-6`; loader rejects a truncated `.bin`, a `.json` with `format: 2` and a flipped byte (temp dir copies); an attack sentence placed at byte offsets 200, 500 and 900 of 2,000 bytes of benign filler is flagged at each offset (Review Focus 1); `score("")`, `score("   ")` and `score("\uD800")` do not throw and the first two return score 0 (Review Focus 3); a 1,200,000-character input returns `truncated: true`; scoring 1 MB takes less than 4× the time of 250 KB plus 200 ms slack and under 3 s in absolute terms (NFR-2); three benign security-documentation paragraphs are not flagged at `fpr1` unless listed in `KNOWN_FALSE_POSITIVES` in the test file (Review Focus 4).
- [ ] **Step 2:** Run `npm test`; expect failure.
- [ ] **Step 3:** Implement. Use `TextEncoder` for UTF-8, `Math.imul` for the FNV multiply, `node:crypto` for SHA-256, `readFileSync` with `new URL("../../models/", import.meta.url)`.
- [ ] **Step 4:** Run `npm test`; expect pass.
- [ ] **Step 5:** Commit `feat: zero-dependency injection detector`.

### Task 5: Proxy, config, CLI and scan integration

**Files:**
- Modify: `src/proxy.ts`, `src/config.ts`, `src/audit.ts`, `src/cli.ts`, `src/scan.ts`, `guardrail.schema.json`, `tests/config.test.ts`, `tests/scan.test.ts`, `tests/e2e/fake-server.mjs`
- Create: `tests/e2e/injection.test.ts`

**Interfaces:**
- Consumes: `InjectionDetector` from Task 4.
- Produces:
  - `type InjectionMode = "off" | "report" | "block"`
  - `GuardrailConfig.injection?: { mode?: InjectionMode; threshold?: number }` (threshold in (0, 1)); `ToolPolicy.injection?: InjectionMode`
  - `ProxyOptions.injection?: { mode: InjectionMode; threshold?: number }`
  - Audit event `{ event: "injection" | "would-injection"; tool?: string; id?: string | number; path: string; score: number; threshold: number; model: string; action: "report" | "block"; truncated: boolean }`
  - CLI: `--detect-injection` (= report), `--detect-injection=report|block`, `--injection-threshold N`; `scan --injection` adds findings with rule `prompt-injection`, label `INJECTION`, line 1, column 1, and no value preview
  - Notice text: ``[mcp-guardrail: withheld — this tool result looks like a prompt injection (score X.XX). Run with --dry-run to inspect.]``
- Behaviour: scoring applies only to responses matched to a tracked `tools/call`; it walks `result.content[*].text` and every string under `result.structuredContent`; it runs on the redacted value; score rounded to 2 decimals in logs; stderr line `tools/call (<tool>): injection suspected at <path> (score 0.97)` with ` — withheld` appended in block mode; precedence per tool > CLI > config > default.

- [ ] **Step 1: Write failing tests.** Config: valid `injection` block accepted; `mode: "blok"` rejected with a suggestion; threshold 0 or 1.5 rejected; per-tool `injection` accepted. Scan: `scanText` with injection enabled returns one `prompt-injection` finding for an attack text and none for benign. End-to-end (extend the fake server with a tool returning three content items, the second an injection, and a tool returning an injected `structuredContent` string plus an AWS-key-shaped secret): report mode forwards the text byte-identical apart from redaction and writes one `injection` audit event; block mode replaces only the injected item (Review Focus 2); dry-run forwards the original line and logs `would-injection`; neither stderr nor the audit file contains a distinctive substring of the injection (NFR-5); redaction and withholding both appear in one valid JSON response (Review Focus 5); per-tool `off` suppresses detection; mode off produces no events.
- [ ] **Step 2:** Run `npm test && npm run test:e2e`; expect failure.
- [ ] **Step 3:** Implement. The detector is constructed once in the proxy constructor only when some effective mode is not `off`, so a bad model file fails at startup (NFR-6).
- [ ] **Step 4:** Run both suites; expect pass, including all pre-existing tests unmodified.
- [ ] **Step 5:** Commit `feat: report or withhold suspected prompt injections in tool results`.

### Task 6: Documentation, CI and release preparation

**Files:**
- Create: `docs/injection-detection.md`, `MODEL_CARD.md`, `scripts/check-release.mjs`
- Modify: `README.md`, `CHANGELOG.md`, `package.json` (version `0.3.0`, script `check:release`), `src/version.ts`, `.github/workflows/ci.yml`

**Interfaces:**
- `scripts/check-release.mjs` exits non-zero if: `package.json` has a non-empty `dependencies`; the `.bin` is 500 KB or larger; the README results table (between `<!-- results:start -->` and `<!-- results:end -->`) differs from the table generated from `docs/benchmarks/results.json`. `node scripts/check-release.mjs --write` rewrites the README table.
- CI adds a `python` job: install `ml/requirements.txt`, run `python -m pytest ml -q`. It does not download datasets.

- [ ] **Step 1:** Write `tests/release.test.ts` asserting `check-release.mjs` passes on the repository and fails on a temp copy whose README table is altered.
- [ ] **Step 2:** Run; expect failure.
- [ ] **Step 3:** Implement the script; write the documents. Limitations in `docs/injection-detection.md` and `MODEL_CARD.md` quote the measured weak protocols from `results.json`.
- [ ] **Step 4:** Run `npm test && npm run test:e2e && npm run check:release && python -m pytest ml -q`; expect pass.
- [ ] **Step 5:** Commit `docs: injection detection guide, model card and 0.3.0 changelog`.
