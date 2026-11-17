# Transformer detector: training and export

Design: [MCPG-DD-002](../../docs/superpowers/specs/2026-11-17-injection-encoder-design.md).

| Module | Does |
|---|---|
| `windows.py` | Token windows (510 tokens, stride 255) and per-window training labels |
| `train.py` | Fine-tuning loop: class-weighted loss, AdamW, mixed precision on GPU |
| `export.py` | ONNX export (TorchScript exporter), int8 quantisation, model directory |
| `score.py` | Reference ONNX scorer; the Node scorer must match it |
| `evaluate.py` | Leave-one-dataset-out benchmark; adds `encoder` (and `promptguard`) to `docs/benchmarks/results.json` |
| `build.py` | Trains the shipped model, calibrates thresholds on held-back groups, exports it |
| `tiny.py` | A tiny tokenizer and ModernBERT model with the same architecture, for tests |
| `make_fixture.py` | Writes `tests/fixtures/encoder-tiny/`, used by the Node parity tests |

## Running it

On a GPU, the simplest path is `notebooks/train_encoder.ipynb` on Colab. By hand:

```bash
pip install -r ml/requirements.txt -r ml/requirements-encoder.txt   # install PyTorch for your platform first
ONNXRUNTIME_NODE_INSTALL=skip npm ci
python -m ml.data.sources                       # sha256 of ml/.cache/dataset.jsonl must start bdd0e335d6f712ad
python -m ml.encoder.evaluate                   # optional: --prompt-guard meta-llama/Llama-Prompt-Guard-2-86M
python -m ml.encoder.build --out models/injection-modernbert-v1
npm run check:release -- --write                # copies the new figures into the README and docs
```

Commit `docs/benchmarks/results.json` and `RESULTS.md`. Publish the model
directory to Hugging Face rather than committing it.

## Tests without a GPU

`python -m pytest ml` trains, exports and scores the tiny model on CPU, so the
whole pipeline runs in CI. `npm test` checks that Node produces the same token
ids and scores (within 1e-4) as `score.py` on `tests/fixtures/encoder-tiny/`.
The tiny model's scores mean nothing; it exists to test the code paths.
