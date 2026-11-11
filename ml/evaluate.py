"""Benchmark the linear detector with whole groups of data held out.

    python -m ml.evaluate

Writes docs/benchmarks/results.json and docs/benchmarks/RESULTS.md. Every
score comes from the int8-quantised model, i.e. the model as shipped.
"""

from __future__ import annotations

import argparse
import json
import math
import time
import zlib
from pathlib import Path

import numpy as np
from scipy.stats import rankdata

from ml.baseline import regex_baseline
from ml.data.sources import SOURCES, read_jsonl
from ml.model import QuantizedModel, featurize_rows, fit, quantize, window_examples

MAX_NEGATIVE_WINDOWS = 8
DOS_TYPES = {"dos", "captcha_dos", "felony_dos", "offensive_email_dos", "swearwords_dos"}


def tpr_at_fpr(pos, neg, fpr: float) -> tuple[float, float]:
    """Detection rate at the lowest threshold whose false-positive rate is at most ``fpr``.

    A text is flagged when ``score >= threshold``.
    """
    pos, neg = np.asarray(pos, dtype=np.float64), np.sort(np.asarray(neg, dtype=np.float64))[::-1]
    allowed = int(math.floor(fpr * len(neg)))
    if allowed >= len(neg):
        threshold = 0.0
    else:
        threshold = float(np.nextafter(neg[allowed], np.inf))
    return (float((pos >= threshold).mean()) if len(pos) else 0.0), threshold


def auroc(pos, neg) -> float:
    pos, neg = np.asarray(pos, dtype=np.float64), np.asarray(neg, dtype=np.float64)
    ranks = rankdata(np.concatenate([pos, neg]))
    return float((ranks[: len(pos)].sum() - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)))


def family(attack: str) -> str:
    """Group attack-type variants so a held-out family is really unseen."""
    if attack.startswith("important_instructions"):
        return "important_instructions"
    if attack in DOS_TYPES:
        return "dos"
    return attack


def fold(key: str, n: int) -> int:
    return zlib.crc32(key.encode("utf-8")) % n


def train_quantized(rows, feats, train_idx) -> QuantizedModel:
    X, y, _ = window_examples([rows[i] for i in train_idx], [feats[i] for i in train_idx], MAX_NEGATIVE_WINDOWS)
    w, bias = fit(X, y)
    q, scale = quantize(w)
    return QuantizedModel(q, scale, bias)


def protocols(rows):
    """Yield ``(name, train_indices, test_indices)`` for every held-out split."""
    src = np.asarray([r["source"] for r in rows])
    label = np.asarray([r["label"] for r in rows])
    group = np.asarray([r["group"] for r in rows])
    fam = np.asarray([family(r["attack"]) for r in rows])
    local_b = np.asarray([r["source"] == "local" and fold(r["group"], 2) == 1 for r in rows])
    local_a = (src == "local") & ~local_b
    idx = np.arange(len(rows))
    # Synthetic rows are training-only: every test set is untouched public data.
    base = local_a | (src == "synthetic")

    yield "lodo/injecagent", idx[(src == "agentdojo") | base], idx[(src == "injecagent") | local_b]
    yield "lodo/agentdojo", idx[(src == "injecagent") | base], idx[(src == "agentdojo") | local_b]

    # Unseen attack style, inside AgentDojo. Benign AgentDojo rows are held out
    # per row (one fifth), so this measures new attacks, not new benign content.
    dojo = src == "agentdojo"
    held_benign = np.asarray([r["source"] == "agentdojo" and not r["label"] and fold(r["id"], 5) == 0 for r in rows])
    for name in sorted(set(fam[dojo & (label == 1)])):
        held_attack = dojo & (label == 1) & (fam == name)
        test = held_attack | held_benign | local_b
        yield f"attack/{name}", idx[(dojo & ~held_attack & ~held_benign) | base], idx[test]

    for suite in sorted(set(group[dojo])):
        held = dojo & (group == suite)
        yield f"suite/{suite}", idx[(~held & (src != "local")) | base], idx[held | local_b]


def evaluate_split(rows, feats, baseline, train_idx, test_idx) -> dict:
    model = train_quantized(rows, feats, train_idx)
    scores = model.score_rows([feats[i] for i in test_idx])
    y = np.asarray([rows[i]["label"] for i in test_idx])
    base = baseline[test_idx]
    pos, neg = scores[y == 1], scores[y == 0]
    return {
        "train_rows": int(len(train_idx)),
        "test_pos": int(len(pos)),
        "test_neg": int(len(neg)),
        "linear": {
            "tpr_fpr1": tpr_at_fpr(pos, neg, 0.01)[0],
            "tpr_fpr01": tpr_at_fpr(pos, neg, 0.001)[0],
            "auroc": auroc(pos, neg),
        },
        "regex": {"tpr": float(base[y == 1].mean()), "fpr": float(base[y == 0].mean())},
    }


def results_table(results: dict) -> str:
    lines = [
        "| Held out | Attacks | Benign | Detected at 1% FP | Detected at 0.1% FP | AUROC | Keyword rules: detected | Keyword rules: FP |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for p in results["protocols"]:
        lin, rx = p["linear"], p["regex"]
        lines.append(
            f"| `{p['name']}` | {p['test_pos']} | {p['test_neg']} | {lin['tpr_fpr1']:.1%} | {lin['tpr_fpr01']:.1%} "
            f"| {lin['auroc']:.3f} | {rx['tpr']:.1%} | {rx['fpr']:.1%} |"
        )
    return "\n".join(lines) + "\n"


REPORT = """# Injection detector benchmark

Generated by `python -m ml.evaluate`. Do not edit by hand.

- Model: `injection-linear-v1` (logistic regression over hashed n-grams, int8 weights)
- Data: AgentDojo `{agentdojo}`, InjecAgent `{injecagent}`, local text files and synthetic training rows ({rows} rows after de-duplication)
- Synthetic rows are used for training only. Every test set below is public data the model was not trained on.
- Every row below trains a fresh model **without** the held-out data, then tests on it.
- "Detected at 1% FP" is the share of held-out attacks flagged when the threshold lets through 1% of held-out benign results.

{table}
## Reading the table

- `lodo/<dataset>`: the whole dataset is unseen in training. This is the closest measure of attacks unlike the training data.
- `attack/<family>`: one AgentDojo attack style is unseen, but the goals the attacks ask for and the surrounding benign content are seen. Treat these rows as optimistic.
- `suite/<suite>`: one AgentDojo environment (its tools and data) is unseen.
- Keyword rules are a fixed regex list ({n_patterns} patterns) with no threshold, so they have one detection rate and one false-positive rate.

Benign counts under 1,000 cannot resolve a 0.1% false-positive rate; in those rows the 0.1% column allows zero false positives.
"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=Path("ml/.cache/dataset.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("docs/benchmarks"))
    args = ap.parse_args()

    rows = read_jsonl(args.dataset)
    started = time.time()
    feats = featurize_rows(rows)
    baseline = np.asarray([regex_baseline(r["text"]) for r in rows])
    from ml.baseline import PATTERNS

    out = []
    for name, train_idx, test_idx in protocols(rows):
        result = {"name": name, **evaluate_split(rows, feats, baseline, train_idx, test_idx)}
        out.append(result)
        print(f"{name:36s} tpr@1%={result['linear']['tpr_fpr1']:.3f} auroc={result['linear']['auroc']:.3f} "
              f"regex={result['regex']['tpr']:.3f}/{result['regex']['fpr']:.3f}  [{time.time() - started:.0f}s]", flush=True)

    results = {
        "model": "injection-linear-v1",
        "data": {name: rev for name, (_, rev) in SOURCES.items()},
        "rows": len(rows),
        "protocols": out,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    (args.out / "RESULTS.md").write_text(
        REPORT.format(table=results_table(results), rows=f"{len(rows):,}", n_patterns=len(PATTERNS), **results["data"]),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
