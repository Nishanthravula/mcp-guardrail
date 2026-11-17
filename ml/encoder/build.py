"""Train the shipped transformer model and write its directory.

    python -m ml.encoder.build --out models/injection-modernbert-v1

About 10% of the data (whole groups) is held back for calibration: the
thresholds come from benign scores the model was not trained on, measured
with the exported int8 ONNX model, exactly as the proxy will run it.
"""

from __future__ import annotations

import argparse
import zlib
from pathlib import Path

import numpy as np

from ml.data.sources import SOURCES, read_jsonl
from ml.encoder.evaluate import DEFAULT_BASE, load_base, torch_score_rows
from ml.encoder.export import export
from ml.encoder.score import OnnxScorer
from ml.encoder.train import train
from ml.train import choose_thresholds

CALIBRATION_SHARE = 0.10
NAME = "injection-modernbert-v1"


def calibration_split(rows) -> tuple[list[int], list[int]]:
    """Whole groups, in a fixed pseudo-random order, until 10% of rows and some benign rows are held back."""
    groups: dict[str, list[int]] = {}
    for i, r in enumerate(rows):
        groups.setdefault(f"{r['source']}:{r['group']}", []).append(i)
    held: list[int] = []
    for key in sorted(groups, key=lambda k: (zlib.crc32(k.encode()), k)):
        if len(held) >= CALIBRATION_SHARE * len(rows) and any(rows[i]["label"] == 0 for i in held):
            break
        held += groups[key]
    held_set = set(held)
    return [i for i in range(len(rows)) if i not in held_set], sorted(held)


def build(rows, make_model, tokenizer, out: Path, *, name: str = NAME, base_model: str = DEFAULT_BASE,
          train_kwargs: dict, data: dict | None = None) -> dict:
    train_idx, cal_idx = calibration_split(rows)
    model = train([rows[i] for i in train_idx], tokenizer, make_model(), **train_kwargs)
    max_length, stride = train_kwargs.get("max_length", 512), train_kwargs.get("stride", 255)
    cal = [rows[i] for i in cal_idx]
    torch_scores = torch_score_rows(model, tokenizer, cal[:200], max_length=max_length, stride=stride)
    placeholder = {"fpr1": 0.5, "fpr01": 0.5, "default": 0.5}
    export(model, tokenizer, out, name=name, base_model=base_model, max_length=max_length, stride=stride,
           thresholds=placeholder, data=data or {})
    scorer = OnnxScorer(out)
    scores = np.array([scorer.score_ids(tokenizer(r["text"], add_special_tokens=False)["input_ids"] if r["text"] else [])
                       for r in cal])
    labels = np.array([r["label"] for r in cal])
    thresholds = choose_thresholds(scores[labels == 0])
    calibration = {
        "rows": len(cal),
        "attacks": int((labels == 1).sum()),
        "benign": int((labels == 0).sum()),
        "detected_at_default": float((scores[labels == 1] >= thresholds["default"]).mean()) if (labels == 1).any() else None,
        "false_positives_at_default": float((scores[labels == 0] >= thresholds["default"]).mean()),
        "max_onnx_torch_diff": float(np.abs(scores[: len(torch_scores)] - torch_scores).max()) if len(torch_scores) else 0.0,
    }
    return export(model, tokenizer, out, name=name, base_model=base_model, max_length=max_length, stride=stride,
                  thresholds=thresholds, data=data or {}, extra={"calibration": calibration })


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=Path("ml/.cache/dataset.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("models") / NAME)
    ap.add_argument("--base-model", default=DEFAULT_BASE)
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--batch-size", type=int, default=16)
    args = ap.parse_args()
    rows = read_jsonl(args.dataset)
    tokenizer, make_model = load_base(args.base_model)
    meta = build(rows, make_model, tokenizer, args.out, base_model=args.base_model,
                 train_kwargs=dict(epochs=args.epochs, lr=args.lr, batch_size=args.batch_size, max_length=512, stride=255),
                 data={name: rev for name, (_, rev) in SOURCES.items()})
    print({k: meta[k] for k in ("name", "thresholds", "calibration", "sha256")})


if __name__ == "__main__":
    main()
