# Model card: injection-linear-v1

## Summary

| | |
|---|---|
| Task | Binary classification: does a tool result contain a prompt injection? |
| Type | Logistic regression over 262,144 hashed n-gram features, int8-quantised |
| Input | Text, scored in overlapping 512-byte windows after normalisation |
| Output | Probability from 0 to 1 per item (maximum over its windows) |
| Files | `models/injection-linear-v1.bin` (weights), `models/injection-linear-v1.json` (metadata) |
| Runtime | Plain TypeScript in this package; no dependency, no network |
| Licence | MIT, same as the package |

<!-- model:start -->
- Default threshold: 0.5
- Grouped 5-fold cross-validation at that threshold: 89.0% of 11,649 attacks detected, 0.13% of 12,696 benign results flagged (training-style data, including synthetic rows)
- Weights: 262,144 bytes, SHA-256 `f17b29a02882f5db72a7b103e8da61d99b21018534dc55a474d6c386cc1f7f3c`
<!-- model:end -->

## Intended use

Flagging suspicious tool results in an MCP proxy, as one layer among several
(tool allow-lists, user confirmation for sensitive actions, least-privilege
credentials). `report` mode is the intended starting point.

## Not intended for

- A sole defence against prompt injection.
- Moderating user messages or detecting jailbreaks typed by the user.
- Non-English text, encoded payloads or adversaries who can probe the model.

## Training data

| Source | Revision | Licence | Attack rows | Benign rows |
|---|---|---|---|---|
| AgentDojo logged agent runs | `089ed468` | MIT | 6,241 | 7,061 |
| InjecAgent | `f19c9f2c` | MIT | 2,108 | 2,202 |
| Local developer text (from `node_modules`) | `package-lock.json` | per package | 0 | 1,033 |
| Synthetic rows written for this project | this repository | MIT | 3,300 | 2,400 |

Details and labelling rules: [ml/data/README.md](ml/data/README.md). No
dataset content is stored in this repository.

## Training procedure

- Features: byte 3-, 4- and 5-grams and word unigrams and bigrams of each
  window, hashed with FNV-1a into 2^18 buckets, binary presence, L2-normalised.
- A window of an attack row is a positive example when it contains at least
  64 bytes of the injection (or all of a shorter one). At most 8 benign
  windows per row are used.
- `LogisticRegression(C=10, solver="liblinear", class_weight="balanced", random_state=0)`.
  Hyper-parameters were fixed in advance and not tuned on test data.
- Weights are quantised to int8 with one scale factor. All reported numbers
  use the quantised model.
- Training is deterministic; a test checks that two runs give identical bytes.

## Evaluation

Protocol: train without a held-out group, test on it. Results:

<!-- results:start -->
| Dataset never seen in training | Attacks | Benign | Detected at 1% false positives | Detected at 0.1% | Keyword rules detect |
|---|---|---|---|---|---|
| InjecAgent | 2,108 | 2,737 | 67.9% | 35.1% | 50.0% |
| AgentDojo | 6,241 | 7,596 | 90.0% | 79.6% | 5.6% |
<!-- results:end -->

Further splits (one attack style or one AgentDojo environment held out) are
in [docs/benchmarks/RESULTS.md](docs/benchmarks/RESULTS.md). The
attack-style rows there are optimistic, because the goals the attacks ask for
are shared between styles.

## Limitations and known failure cases

See [docs/injection-detection.md](docs/injection-detection.md#what-it-misses).
In short: misses translated, encoded, look-alike-character and politely
indirect attacks; flags some correspondence and policy text addressed to
people. Both lists are pinned by tests.

## Bias and data caveats

- English only.
- Attack rows are template-generated; many differ only in a name.
- The synthetic rows reflect one author's idea of an injection.
- Benign data under-represents web pages, chat and email.

## Retraining

See "Reproducing the numbers" in
[docs/injection-detection.md](docs/injection-detection.md#reproducing-the-numbers).
A model with different feature settings must ship under a new name; the
loader rejects a weights file whose metadata does not match the code.
