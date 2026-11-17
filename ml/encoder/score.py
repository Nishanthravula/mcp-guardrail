"""Reference scorer for an exported model directory (ONNX Runtime, CPU).

The Node scorer must match this: same normalisation, windows, batching and
probability. Used for benchmarking and for the golden fixture.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from ml.encoder.windows import token_windows, wrap
from ml.features import normalize

BATCH = 8
MAX_ITEM_CHARS = 1_048_576


def softmax_attack(logits: np.ndarray) -> np.ndarray:
    """Probability of class 1 for each row of [batch, 2] logits."""
    z = logits - logits.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e[:, 1] / e.sum(axis=1)


class OnnxScorer:
    def __init__(self, directory):
        import onnxruntime as ort
        from transformers import PreTrainedTokenizerFast

        d = Path(directory)
        self.meta = json.loads((d / "guardrail.json").read_text(encoding="utf-8"))
        blob = (d / "model.onnx").read_bytes()
        if hashlib.sha256(blob).hexdigest() != self.meta["sha256"]:
            raise ValueError(f"{d}: model.onnx failed its checksum")
        self.tokenizer = PreTrainedTokenizerFast.from_pretrained(str(d))
        self.tokenizer.model_max_length = 10**9  # texts are windowed, never truncated
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1  # deterministic summation order
        self.session = ort.InferenceSession(blob, opts, providers=["CPUExecutionProvider"])

    def token_ids(self, raw: str) -> list[int]:
        if len(raw) > MAX_ITEM_CHARS:
            half = MAX_ITEM_CHARS // 2
            raw = raw[:half] + " " + raw[-half:]
        text = normalize(raw)
        return self.tokenizer(text, add_special_tokens=False)["input_ids"] if text else []

    def score_ids(self, ids: list[int]) -> float:
        m = self.meta
        seqs = [wrap(ids[s:e], m["clsId"], m["sepId"]) for s, e in token_windows(len(ids), m["maxLength"], m["stride"])]
        best = 0.0
        for b in range(0, len(seqs), BATCH):
            chunk = seqs[b : b + BATCH]
            width = max(len(s) for s in chunk)
            x = np.full((len(chunk), width), m["padId"], dtype=np.int64)
            mask = np.zeros((len(chunk), width), dtype=np.int64)
            for i, s in enumerate(chunk):
                x[i, : len(s)] = s
                mask[i, : len(s)] = 1
            logits = self.session.run(None, {"input_ids": x, "attention_mask": mask})[0]
            best = max(best, float(softmax_attack(logits.astype(np.float64)).max()))
        return best

    def score_text(self, raw: str) -> float:
        return self.score_ids(self.token_ids(raw))
