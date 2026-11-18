# Design Document: Transformer Injection Detector (Phase 2)

| | |
|---|---|
| **Document ID** | MCPG-DD-002 |
| **Project** | mcp-guardrail (`@nishanthravula/mcp-guardrail`) |
| **Author** | Nishanth Ravula |
| **Status** | Approved |
| **Version** | 1.1 |
| **Created** | 2026-11-17 |
| **Target release** | 0.4.0 |
| **Parent** | MCPG-DD-001, section 6.1 (tier 2) and milestone M7 |
| **Classification** | Public (open-source project) |

## Revision History

| Version | Date | Author | Summary |
|---|---|---|---|
| 1.0 | 2026-11-17 | N. Ravula | Design approved in review: ModernBERT-base, `onnxruntime-node` with `@huggingface/tokenizers` |
| 1.1 | 2026-11-17 | N. Ravula | Built. Added section 10, recording where the implementation differs from this design |

Requirement keywords follow RFC 2119, as in MCPG-DD-001.

---

## 1. Summary

Phase 1 shipped a built-in linear detector. This phase adds an optional
transformer detector: ModernBERT-base fine-tuned on the same data, exported
to ONNX, and run in Node through optional packages. The linear model stays
the default. The work also adds the encoder to the benchmark next to the
linear model and an external baseline (Meta Prompt Guard 2).

Fine-tuning needs a GPU and access to Hugging Face, which the build
environment does not have. Every part of the pipeline is therefore built and
tested here with a tiny, randomly initialised model of the same architecture,
and the maintainer runs one notebook to produce the real model and its
benchmark figures.

## 2. Decisions

| ID | Decision | Alternatives considered |
|---|---|---|
| D1 | Base model: `answerdotai/ModernBERT-base` | A model of 20–30M parameters: smaller and faster, expected to be less accurate |
| D2 | Node runtime: `onnxruntime-node` and `@huggingface/tokenizers`, as optional peer dependencies | `@huggingface/transformers`: simpler, but a much larger install including an image library |
| D3 | The model is distributed outside npm (Hugging Face, or any directory) and selected by path | Bundling: impossible at this size |
| D4 | The proxy's response path becomes asynchronous, with output order preserved | None: `onnxruntime-node` has no synchronous inference |
| D5 | Text is normalised exactly as for the linear model before tokenising | Raw text: would need a second dataset, since the stored dataset holds normalised text |
| D6 | `scan --injection` keeps using the built-in model | An asynchronous scan API: a breaking change to `scanText` and `scanPaths` for little gain |

## 3. Requirements

### 3.1 Functional

| ID | Requirement |
|---|---|
| FR-21 | `injection.model` (config) and `--injection-model <dir>` (CLI) MUST select a model directory; `builtin` or no value MUST keep the linear model |
| FR-22 | The proxy MUST score with the selected model and otherwise behave as in phase 1: modes, per-tool overrides, notice text, audit events |
| FR-23 | Responses MUST reach the host in the order the server sent them, whatever the scoring time |
| FR-24 | If scoring a result fails at run time, the proxy MUST log an `injection-error` event; in `block` mode it MUST withhold the item, in `report` mode it MUST forward it |
| FR-25 | The library MUST export `EncoderDetector` with `static load(dir, options)` and `score(text): Promise<InjectionResult>` |
| FR-26 | `scan --injection-model` MUST be rejected with a message saying scan uses the built-in model |
| FR-27 | The training notebook MUST build the dataset, train, evaluate, export and optionally upload the model in one run |

### 3.2 Non-functional

| ID | Requirement |
|---|---|
| NFR-21 | `package.json` MUST still declare no `dependencies`; the two packages are optional `peerDependencies` |
| NFR-22 | A missing peer package, a missing file or a checksum mismatch MUST stop start-up with a message naming the fix |
| NFR-23 | Node and Python ONNX scores MUST agree within 1e-4, and token ids MUST be identical, on the committed golden texts |
| NFR-24 | The phase 1 dataset MUST be rebuilt byte-identically, so phase 1 figures stay valid |
| NFR-25 | No figure for the encoder is published until produced by the maintainer's run; the release check MUST tolerate its absence and verify it when present |
| NFR-26 | All existing tests MUST pass unmodified |

## 4. Model directory format

```
<dir>/
  model.onnx              int8-quantised ONNX graph, inputs input_ids and attention_mask (int64), output logits [batch, 2]
  tokenizer.json          Hugging Face fast-tokenizer definition
  tokenizer_config.json
  guardrail.json          metadata, below
```

`guardrail.json`:

```json
{"format": 1, "kind": "encoder", "name": "injection-modernbert-v1",
 "baseModel": "answerdotai/ModernBERT-base", "maxLength": 512, "stride": 255,
 "clsId": 50281, "sepId": 50282, "padId": 50283,
 "thresholds": {"fpr1": 0.0, "fpr01": 0.0, "default": 0.5},
 "sha256": "<hex of model.onnx>", "data": {"agentdojo": "...", "injecagent": "..."}}
```

(The ids shown are placeholders; the real values come from the tokenizer.)

## 5. Scoring

1. Normalise the text with the phase 1 `normalize`.
2. Tokenise without special tokens.
3. Cut the ids into windows of `maxLength − 2` tokens with stride `stride`; the
   last window ends at the last token. Wrap each in `clsId … sepId`.
4. Run the windows in batches of 8, padded with `padId` and masked.
5. The item's score is the highest softmax probability of class 1. Items over
   the phase 1 size cap are scored on both ends, as before.

Training labels a window as an attack when it holds at least 16 tokens of an
injection (or all of a shorter one), and leaves out windows with a smaller
non-zero overlap.

## 6. Proxy changes

Server output lines enter a promise chain. Each line is processed (redaction
unchanged, then awaited scoring) and written only after every earlier line has
been written. On server exit, the chain drains before the process exits.
With the built-in model the scorer resolves immediately, so behaviour is
unchanged apart from running in a microtask.

## 7. Evidence

| Item | Produced by | Where |
|---|---|---|
| Pipeline correctness | Tests with a tiny model trained and exported here | `ml/tests`, `tests/encoder.test.ts`, `tests/e2e/encoder.test.ts` |
| Node vs Python parity | Golden vectors from the tiny model | `tests/fixtures/encoder-tiny/` |
| Encoder accuracy | `python -m ml.encoder.evaluate` on a GPU (leave-one-dataset-out, same splits as phase 1) | `results.json` gains an `encoder` entry per held-out dataset |
| Prompt Guard 2 | Same script with `--prompt-guard` (needs access to the gated model) | `results.json` gains a `promptguard` entry |
| Shipped thresholds | Benign scores on a 10% grouped calibration split the model was not trained on | `guardrail.json` |

## 8. Out of scope

The live agent attack test (needs an LLM API key; next phase), a hosted demo,
GPU inference in the proxy, and models other than ModernBERT-base.

## 9. Risks

| Risk | Handling |
|---|---|
| ModernBERT does not export cleanly to ONNX | Export is exercised in CI with the tiny model of the same architecture |
| The JavaScript tokenizer differs from the Python one | Token-id parity test on golden texts, including non-ASCII |
| Asynchronous output reorders or loses messages | Ordering test with many concurrent calls; existing end-to-end suite unchanged |
| Start-up slowed by hashing a large model file | Measured and documented |
| The encoder is not better than the linear model | Reported as measured; the linear model stays the default |

## 10. Implementation Record

| Area | Design | As built | Reason |
|---|---|---|---|
| ONNX export | Not specified | TorchScript exporter (`dynamo=False`), opset 17 | The dynamo exporter's graph failed ONNX Runtime shape inference after quantisation in a trial |
| Benchmark scoring (section 7) | The shipped model | PyTorch on the GPU, before quantisation; the build records the largest ONNX–PyTorch difference on the calibration rows | Scoring about 13,000 rows on a Colab CPU is too slow |
| Calibration split | 10% grouped | Whole groups in a fixed checksum order until at least 10% of rows, including some benign rows, are held back | Guarantees benign rows to set thresholds from, however groups are sized |
| Message processing (section 6) | Ordered chain | Strictly one message at a time; an unexpected internal error exits the proxy with code 1 instead of forwarding a possibly unredacted line | Simplest way to guarantee order; matches the previous crash behaviour |
| Benign source (NFR-24) | Rebuild identically | Local text read only from the 105 packages in `ml/data/local-packages.txt` | Installing the two dev packages added 15 packages to `node_modules`, which would have changed the dataset |
| Test model | Tiny ModernBERT | Three layers with global attention every third layer, like ModernBERT-base's mix of global and sliding-window layers | Exercises the sliding-window path in export and inference |

Not yet done: the GPU training run, publishing the model, and the encoder and Prompt Guard 2 figures.
