"""Linear injection classifier: window labelling, training, quantisation, scoring."""

from __future__ import annotations

import math

import numpy as np
from scipy import sparse
from sklearn.linear_model import LogisticRegression

from ml.features import N_FEATURES, featurize_fast, windows

MIN_OVERLAP = 64  # bytes of an injection a window must contain to count as an attack window


def featurize_rows(rows) -> list[list[np.ndarray]]:
    """Feature indices of every window of every row."""
    out = []
    for row in rows:
        data = row["text"].encode("utf-8")
        out.append([featurize_fast(data[s:e]) for s, e in windows(len(data))])
    return out


def _window_label(row, start: int, end: int) -> int | None:
    """1 = attack window, 0 = benign window, None = ambiguous (left out of training)."""
    if not row["label"]:
        return 0
    best = None
    for s, e in row["spans"]:
        overlap = min(end, e) - max(start, s)
        if overlap >= min(MIN_OVERLAP, e - s):
            return 1
        if overlap > 0:
            best = "partial"
    return None if best else 0


def window_examples(rows, feats=None, max_negative_windows: int | None = None):
    """Training matrix of L2-normalised binary window features.

    Returns ``(X, y, row_index)``. ``max_negative_windows`` keeps at most that
    many evenly spaced benign windows per row, which bounds memory on long
    documents without changing which attacks are seen.
    """
    feats = feats if feats is not None else featurize_rows(rows)
    indices, indptr, data, y, row_index = [], [0], [], [], []
    for r, (row, row_feats) in enumerate(zip(rows, feats)):
        n_bytes = len(row["text"].encode("utf-8"))
        labelled = [(_window_label(row, s, e), f) for (s, e), f in zip(windows(n_bytes), row_feats)]
        negatives = [f for label, f in labelled if label == 0]
        if max_negative_windows is not None and len(negatives) > max_negative_windows:
            keep = np.linspace(0, len(negatives) - 1, max_negative_windows).round().astype(int)
            kept = {id(negatives[i]) for i in keep}
            labelled = [(label, f) for label, f in labelled if label != 0 or id(f) in kept]
        for label, f in labelled:
            if label is None or len(f) == 0:
                continue
            indices.append(f)
            data.append(np.full(len(f), 1.0 / math.sqrt(len(f)), dtype=np.float32))
            indptr.append(indptr[-1] + len(f))
            y.append(label)
            row_index.append(r)
    X = sparse.csr_matrix(
        (
            np.concatenate(data) if data else np.zeros(0, dtype=np.float32),
            np.concatenate(indices).astype(np.int32) if indices else np.zeros(0, dtype=np.int32),
            np.asarray(indptr, dtype=np.int64),
        ),
        shape=(len(y), N_FEATURES),
    )
    return X, np.asarray(y, dtype=np.int8), np.asarray(row_index, dtype=np.int64)


def fit(X, y) -> tuple[np.ndarray, float]:
    """Train the classifier. Hyper-parameters are fixed in advance, not tuned on test data."""
    clf = LogisticRegression(C=10.0, solver="liblinear", class_weight="balanced", random_state=0)
    clf.fit(X, y)
    return clf.coef_.ravel().astype(np.float64), float(clf.intercept_[0])


def quantize(w: np.ndarray) -> tuple[np.ndarray, float]:
    """Map float weights to int8 with one shared scale."""
    peak = float(np.abs(w).max()) if w.size else 0.0
    if peak == 0.0:
        return np.zeros(w.shape, dtype=np.int8), 1.0
    scale = peak / 127.0
    return np.clip(np.rint(w / scale), -127, 127).astype(np.int8), scale


class QuantizedModel:
    """The model exactly as shipped: int8 weights, one scale, one bias."""

    def __init__(self, weights: np.ndarray, scale: float, bias: float):
        self.weights = weights.astype(np.int64)
        self.scale = float(scale)
        self.bias = float(bias)

    def score_features(self, idx: np.ndarray) -> float:
        k = len(idx)
        if k == 0:
            return 0.0
        s = self.bias + self.scale * float(self.weights[idx].sum()) / math.sqrt(k)
        return 1.0 / (1.0 + math.exp(-s))

    def score_window(self, window: bytes) -> float:
        return self.score_features(featurize_fast(window))

    def score_text(self, norm: str) -> float:
        data = norm.encode("utf-8")
        return max((self.score_window(data[s:e]) for s, e in windows(len(data))), default=0.0)

    def score_rows(self, feats) -> np.ndarray:
        return np.asarray([max((self.score_features(f) for f in row), default=0.0) for row in feats])


def load_model(directory, name: str = "injection-linear-v1") -> tuple[QuantizedModel, dict]:
    """Load a shipped model and its metadata, verifying the checksum."""
    import hashlib
    import json
    from pathlib import Path

    directory = Path(directory)
    meta = json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
    blob = (directory / f"{name}.bin").read_bytes()
    if hashlib.sha256(blob).hexdigest() != meta["sha256"] or len(blob) != meta["nFeatures"]:
        raise ValueError(f"{name}: weights do not match metadata")
    return QuantizedModel(np.frombuffer(blob, dtype=np.int8), meta["scale"], meta["bias"]), meta
