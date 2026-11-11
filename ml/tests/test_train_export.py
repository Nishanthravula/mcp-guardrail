import hashlib
import json

import numpy as np

from ml.export_golden import HAND_WRITTEN, generate_cases
from ml.features import N_FEATURES, normalize
from ml.model import QuantizedModel, load_model
from ml.train import choose_thresholds, write_model


def test_default_threshold_is_never_below_one_half():
    t = choose_thresholds(np.linspace(0.0, 0.2, 1000))
    assert t["fpr1"] < 0.5 and t["default"] == 0.5
    assert t["fpr01"] >= t["fpr1"]


def test_default_threshold_follows_fpr1_when_benign_scores_run_high():
    scores = np.concatenate([np.zeros(900), np.full(100, 0.8)])
    t = choose_thresholds(scores)
    assert t["fpr1"] > 0.8 and t["default"] == t["fpr1"]


def test_write_model_round_trips_and_records_checksum(tmp_path):
    q = (np.arange(N_FEATURES) % 255 - 127).astype(np.int8)
    write_model(tmp_path, "m1", q, 0.25, -1.5, {"fpr1": 0.6, "fpr01": 0.9, "default": 0.6}, {"note": "x"})
    meta = json.loads((tmp_path / "m1.json").read_text())
    blob = (tmp_path / "m1.bin").read_bytes()
    assert len(blob) == N_FEATURES and meta["sha256"] == hashlib.sha256(blob).hexdigest()
    assert (meta["format"], meta["nFeatures"], meta["window"], meta["stride"]) == (1, N_FEATURES, 512, 256)
    model, loaded = load_model(tmp_path, "m1")
    assert isinstance(model, QuantizedModel) and loaded["thresholds"]["default"] == 0.6
    assert (model.weights == q).all() and model.scale == 0.25 and model.bias == -1.5


def test_golden_cases_are_deterministic_and_varied():
    a, b = generate_cases(), generate_cases()
    assert a == b and len(a) >= 500
    assert "" in a and any(len(t.encode()) > 1024 for t in a)
    assert any(any(ord(c) > 0x7F for c in t) for t in a)
    assert sum(normalize(t) != t for t in a) > 400  # most cases exercise normalisation
    assert all(h in a for h in HAND_WRITTEN)
