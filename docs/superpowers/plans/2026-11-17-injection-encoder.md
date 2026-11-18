# Transformer Injection Detector (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let mcp-guardrail score tool results with an optional fine-tuned ModernBERT model, with the full pipeline tested here on a tiny model and a one-notebook path for the real one.

**Architecture:** Python (`ml/encoder/`) fine-tunes, exports to ONNX with the TorchScript exporter (`dynamo=False`), quantises to int8 and writes a model directory. Node loads it through optional `onnxruntime-node` and `@huggingface/tokenizers`. The proxy's server-to-host path becomes a promise chain that preserves order.

**Tech Stack:** PyTorch, transformers (ModernBERT), onnxruntime, tokenizers; TypeScript with `onnxruntime-node` and `@huggingface/tokenizers` as optional peers.

**Spec:** `docs/superpowers/specs/2026-11-17-injection-encoder-design.md` (MCPG-DD-002)

## Global Constraints

- `package.json` keeps no `dependencies`; the two packages are optional `peerDependencies` and `devDependencies`.
- Install the dev packages with `ONNXRUNTIME_NODE_INSTALL=skip` (CPU files are bundled; the GPU download is blocked here).
- Tokens: windows of `maxLength − 2` ids, stride `stride`, last window aligned to the end, each wrapped `clsId … sepId`, batches of 8 padded with `padId`.
- Node vs Python: identical token ids, scores within 1e-4.
- Phase 1 dataset rebuilt byte-identically (sha256 `bdd0e335…`).
- No encoder figure is committed from this workspace: only the maintainer's GPU run produces them.
- Existing tests pass unmodified.

## Review Focus

1. A burst of tool results scored slowly must still reach the host in order, interleaved with untouched messages. Test in Task 5.
2. Scoring that throws at run time: block mode withholds, report mode forwards, an `injection-error` event is logged. Test in Task 5.
3. Server exit while results are still being scored: every queued result is written before the process exits. Test in Task 5.
4. Model directory with a missing tokenizer, a modified `model.onnx`, or the peer packages absent: start-up fails with the fix named. Test in Task 4.
5. Text longer than one window and empty text: correct windowing, score 0 for empty. Test in Tasks 1 and 4.

---

### Task 1: Token windows and labels (Python)

**Files:** Create `ml/encoder/__init__.py`, `ml/encoder/windows.py`, `ml/encoder/tiny.py`, `ml/tests/test_encoder_windows.py`

**Interfaces:**
- `token_windows(n: int, max_length: int, stride: int) -> list[tuple[int, int]]` (token index ranges; `max_length` counts the two special tokens)
- `wrap(ids: list[int], cls_id: int, sep_id: int) -> list[int]`
- `label_windows(row: dict, tokenizer, max_length, stride) -> list[tuple[list[int], int | None]]` (wrapped ids, label 1/0/None) using `return_offsets_mapping`; spans are byte offsets in the normalised UTF-8 text; attack window = at least `min(16, span tokens)` tokens inside a span; partial overlap = None
- `tiny.build_tokenizer(texts) -> PreTrainedTokenizerFast` (byte-level BPE, vocab 600, specials `[UNK] [CLS] [SEP] [PAD] [MASK]`); `tiny.build_model(tokenizer, seed=0)` (ModernBERT, hidden 32, 2 layers)

- [ ] Tests: `token_windows(0, 8, 3) == []`; `(5, 8, 3) == [(0, 5)]`; `(6, 8, 3) == [(0, 6)]`; `(10, 8, 3) == [(0, 6), (3, 9), (4, 10)]`; `wrap` adds cls/sep; `label_windows` on a row whose span covers the last 30 tokens of 60 labels the first window 0 and the last 1 and never labels a window with 1–15 span tokens; benign rows label all 0.
- [ ] Run, see failure; implement; run, pass; commit `feat(ml): token windows and labels for the encoder`.

### Task 2: Train, export, reference scorer, golden fixture

**Files:** Create `ml/encoder/train.py`, `ml/encoder/export.py`, `ml/encoder/score.py`, `ml/encoder/make_fixture.py`, `ml/tests/test_encoder_pipeline.py`, `tests/fixtures/encoder-tiny/` (generated)

**Interfaces:**
- `train(rows, tokenizer, model, *, epochs=1, lr=2e-5, batch_size=16, max_negative_windows=8, seed=0, device=None) -> model` (class-weighted cross-entropy, AdamW, linear decay)
- `export(model, tokenizer, out_dir, *, name, base_model, max_length, stride, thresholds, data) -> dict` (writes the four files of DD-002 §4; returns metadata)
- `OnnxScorer(dir).score_text(raw: str) -> float` (normalise, window, batch 8, softmax class 1, max; empty → 0.0) and `.token_ids(raw) -> list[int]`
- `make_fixture` writes `tests/fixtures/encoder-tiny/` plus `golden.json` (`{"cases": [{"text", "ids", "score"}]}`) using `ml.export_golden.generate_cases()[:80]`, a 2,000-character text and the attack/benign sentences used by the TS tests.

- [ ] Tests: export writes four files and `sha256` matches `model.onnx`; ONNX scores match PyTorch within 1e-2 after int8 quantisation; `score_text("") == 0`; training 2 epochs on 40 toy rows is deterministic for a fixed seed and moves the attack score above the benign one.
- [ ] Run, fail; implement; pass; generate the fixture; commit `feat(ml): fine-tune, export and score the encoder`.

### Task 3: Encoder benchmark and calibration

**Files:** Create `ml/encoder/evaluate.py`, `ml/encoder/build.py`, `ml/tests/test_encoder_evaluate.py`; Modify `ml/evaluate.py` (`results_table`), `scripts/check-release.mjs`

**Interfaces:**
- `evaluate.run(rows, make_model, tokenizer, protocols=("lodo/injecagent", "lodo/agentdojo"), prompt_guard: str | None) -> dict` adds `encoder` (and `promptguard`) metrics to matching entries of `results.json`
- `build.main()`: grouped 90/10 split, train on 90%, thresholds from benign scores on the 10%, export the shipped directory
- `results_table` adds "Encoder at 1% FP" and "Prompt Guard 2" columns only when any protocol has them; `check-release` adds them to the README table the same way

- [ ] Tests: `run` on a tiny synthetic set with the tiny model writes `encoder` metrics only to the requested protocols; table columns appear only when present; check-release passes with and without encoder entries.
- [ ] Run, fail; implement; pass; commit `feat(ml): encoder benchmark and calibrated export`.

### Task 4: EncoderDetector (TypeScript)

**Files:** Create `src/injection/encoder.ts`, `src/injection/scorer.ts`, `tests/encoder.test.ts`; Modify `src/index.ts`, `package.json`

**Interfaces:**
- `interface Scorer { readonly threshold: number; readonly modelName: string; score(text: string): InjectionResult | Promise<InjectionResult> }` (the linear `InjectionDetector` already satisfies it)
- `class EncoderDetector implements Scorer { static load(dir: string, opts?: { threshold?: number }): Promise<EncoderDetector>; tokenIds(text: string): number[]; score(text: string): Promise<InjectionResult> }`
- `loadScorer(model: string | undefined, threshold?: number): Promise<Scorer>` (`undefined` or `"builtin"` → linear)
- Errors start with `mcp-guardrail: injection model`; a missing peer says `npm install onnxruntime-node @huggingface/tokenizers`.

- [ ] Tests: every golden case has identical ids and score within 1e-4; empty text → score 0, not flagged; a 2,000-character text yields `windowStart` in tokens' byte space ≥ 0; threshold validation; load fails on a missing tokenizer file, a modified `model.onnx` (checksum), `format: 2`, `kind: "linear"`; `loadScorer("builtin")` returns the linear detector.
- [ ] Run, fail; implement; pass; commit `feat: optional transformer detector`.

### Task 5: Asynchronous proxy, config and CLI

**Files:** Modify `src/proxy.ts`, `src/config.ts`, `src/cli.ts`, `src/audit.ts`, `guardrail.schema.json`, `tests/config.test.ts`, `tests/e2e/fake-server.mjs`; Create `tests/e2e/encoder.test.ts`

**Interfaces:**
- `InjectionConfig.model?: string`; CLI `--injection-model <dir>`; `ProxyOptions.injection.scorer?: Scorer` (constructed by the CLI before `start()`; the proxy keeps building the linear detector itself when none is passed)
- `ProxyOptions.injection.scorer` lets tests inject a slow or failing scorer
- Audit event `{ event: "injection-error"; tool; id; path; action: "report" | "block"; error: string }` (error message only)
- Notice for a withheld item after an error: `[mcp-guardrail: withheld — this tool result could not be checked for prompt injection.]`

- [ ] Tests: config accepts `injection.model` string and rejects a number; e2e with `--injection-model tests/fixtures/encoder-tiny --injection-threshold 0.000001` in block mode withholds every scored item; 40 calls interleaved with 40 non-tool responses arrive in order with a slow scorer (unit-level, through `GuardrailProxy` with an injected scorer that resolves in reverse order); a throwing scorer gives `injection-error` and the correct block/report behaviour; server exit while 20 results are pending still writes all 20; `scan --injection-model x` exits 2.
- [ ] Run, fail; implement; pass, including all existing suites; commit `feat: score tool results with an optional transformer model`.

### Task 6: Notebook, documentation, CI

**Files:** Create `ml/encoder/README.md`, `notebooks/train_encoder.ipynb`, `ml/requirements-encoder.txt`; Modify `docs/injection-detection.md`, `MODEL_CARD.md`, `README.md`, `CHANGELOG.md` (Unreleased), `ml/data/README.md`, `.github/workflows/ci.yml`

- [ ] CI: the Node job installs with `ONNXRUNTIME_NODE_INSTALL=skip`; the `ml` job installs CPU PyTorch and runs all Python tests including the tiny-model pipeline.
- [ ] Notebook cells: clone, install, build dataset (installs Node if missing), `python -m ml.encoder.evaluate`, `python -m ml.encoder.build`, optional Hugging Face upload, then print the files to commit (`docs/benchmarks/results.json`).
- [ ] Run every suite and `npm run check:release`; commit `docs: transformer detector guide, notebook and CI`.
