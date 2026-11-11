"""Train the shipped model on all data and write it to ``models/``.

    python -m ml.train

Thresholds come from out-of-fold benign scores under grouped 5-fold
cross-validation, so they are never measured on text the scoring model saw.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from ml.data.sources import SOURCES, read_jsonl
from ml.evaluate import MAX_NEGATIVE_WINDOWS, fold, tpr_at_fpr, train_quantized
from ml.features import N_FEATURES, STRIDE, WINDOW
from ml.model import featurize_rows

NAME = "injection-linear-v1"
FOLDS = 5
MIN_DEFAULT_THRESHOLD = 0.5


def choose_thresholds(benign_scores) -> dict:
    """Thresholds at 1% and 0.1% false positives, plus the default the proxy uses.

    The default never drops below 0.5: the benign training text is narrower
    than real tool traffic, so a threshold tuned to it alone would be too eager.
    """
    fpr1 = tpr_at_fpr([], benign_scores, 0.01)[1]
    fpr01 = tpr_at_fpr([], benign_scores, 0.001)[1]
    return {"fpr1": fpr1, "fpr01": fpr01, "default": max(fpr1, MIN_DEFAULT_THRESHOLD)}


def write_model(directory: Path, name: str, weights: np.ndarray, scale: float, bias: float, thresholds: dict, extra: dict) -> None:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    blob = weights.astype(np.int8).tobytes()
    (directory / f"{name}.bin").write_bytes(blob)
    meta = {
        "format": 1,
        "name": name,
        "nFeatures": N_FEATURES,
        "window": WINDOW,
        "stride": STRIDE,
        "scale": float(scale),
        "bias": float(bias),
        "thresholds": {k: float(v) for k, v in thresholds.items()},
        "sha256": hashlib.sha256(blob).hexdigest(),
        **extra,
    }
    (directory / f"{name}.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=Path("ml/.cache/dataset.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("models"))
    args = ap.parse_args()

    rows = read_jsonl(args.dataset)
    feats = featurize_rows(rows)
    labels = np.asarray([r["label"] for r in rows])
    folds = np.asarray([fold(f"{r['source']}:{r['group']}", FOLDS) for r in rows])
    oof = np.zeros(len(rows))
    idx = np.arange(len(rows))
    for k in range(FOLDS):
        model = train_quantized(rows, feats, idx[folds != k])
        held = idx[folds == k]
        oof[held] = model.score_rows([feats[i] for i in held])
        print(f"fold {k}: {len(held)} held-out rows", flush=True)

    thresholds = choose_thresholds(oof[labels == 0])
    cv = {
        "folds": FOLDS,
        "attacks": int((labels == 1).sum()),
        "benign": int((labels == 0).sum()),
        "detected_at_default": float((oof[labels == 1] >= thresholds["default"]).mean()),
        "false_positives_at_default": float((oof[labels == 0] >= thresholds["default"]).mean()),
        "detected_at_fpr1": float((oof[labels == 1] >= thresholds["fpr1"]).mean()),
        "detected_at_fpr01": float((oof[labels == 1] >= thresholds["fpr01"]).mean()),
    }
    final = train_quantized(rows, feats, idx)
    write_model(
        args.out, NAME, final.weights.astype(np.int8), final.scale, final.bias, thresholds,
        {"data": {name: rev for name, (_, rev) in SOURCES.items()}, "rows": len(rows),
         "maxNegativeWindows": MAX_NEGATIVE_WINDOWS, "cv": cv},
    )
    print(json.dumps({"thresholds": thresholds, "cv": cv}, indent=2))


if __name__ == "__main__":
    main()
