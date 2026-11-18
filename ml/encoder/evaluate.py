"""Benchmark the transformer detector on the phase 1 held-out datasets.

    python -m ml.encoder.evaluate [--prompt-guard meta-llama/Llama-Prompt-Guard-2-86M]

For each held-out dataset a fresh model is fine-tuned without it and tested on
it. Results are added to docs/benchmarks/results.json next to the linear
model's, and RESULTS.md is regenerated. Needs a GPU for ModernBERT-base.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from ml.data.sources import read_jsonl
from ml.encoder.train import pad_batch, train
from ml.encoder.windows import token_windows, wrap
from ml.evaluate import auroc, protocols, tpr_at_fpr, write_report

DEFAULT_BASE = "answerdotai/ModernBERT-base"
HELD_OUT = ("lodo/injecagent", "lodo/agentdojo")


def metrics(scores, labels) -> dict:
    scores, labels = np.asarray(scores), np.asarray(labels)
    pos, neg = scores[labels == 1], scores[labels == 0]
    return {"tpr_fpr1": tpr_at_fpr(pos, neg, 0.01)[0], "tpr_fpr01": tpr_at_fpr(pos, neg, 0.001)[0], "auroc": auroc(pos, neg)}


def torch_score_rows(model, tokenizer, rows, *, max_length: int, stride: int, batch_size: int = 64,
                     cls_id=None, sep_id=None, pad_id=None, attack_index: int = 1) -> np.ndarray:
    """Highest window probability per row, on whatever device the model is on."""
    import torch

    cls_id = tokenizer.cls_token_id if cls_id is None else cls_id
    sep_id = tokenizer.sep_token_id if sep_id is None else sep_id
    pad_id = tokenizer.pad_token_id if pad_id is None else pad_id
    device = next(model.parameters()).device
    windows, owner = [], []
    for r, row in enumerate(rows):
        ids = tokenizer(row["text"], add_special_tokens=False)["input_ids"] if row["text"] else []
        for s, e in token_windows(len(ids), max_length, stride):
            windows.append(wrap(ids[s:e], cls_id, sep_id))
            owner.append(r)
    best = np.zeros(len(rows))
    order = sorted(range(len(windows)), key=lambda i: len(windows[i]))
    model.eval()
    with torch.no_grad():
        for b in range(0, len(order), batch_size):
            idx = order[b : b + batch_size]
            ids, mask = pad_batch([windows[i] for i in idx], pad_id)
            with torch.autocast(device_type="cuda", dtype=torch.bfloat16, enabled=device.type == "cuda" and torch.cuda.is_bf16_supported()):
                logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
            p = torch.softmax(logits.float(), dim=-1)[:, attack_index].cpu().numpy()
            for i, v in zip(idx, p):
                best[owner[i]] = max(best[owner[i]], float(v))
    return best


def run(rows, results: dict, make_model, tokenizer, *, train_kwargs: dict, base_model: str,
        prompt_guard: str | None = None, held_out=HELD_OUT) -> dict:
    """Add ``encoder`` (and ``promptguard``) metrics to the matching protocols of ``results``."""
    by_name = {p["name"]: p for p in results["protocols"]}
    splits = {name: (tr, te) for name, tr, te in protocols(rows) if name in held_out}
    pg = _load_prompt_guard(prompt_guard) if prompt_guard else None
    for name in held_out:
        train_idx, test_idx = splits[name]
        model = train([rows[i] for i in train_idx], tokenizer, make_model(), **train_kwargs)
        test_rows = [rows[i] for i in test_idx]
        labels = [r["label"] for r in test_rows]
        scores = torch_score_rows(model, tokenizer, test_rows, max_length=train_kwargs.get("max_length", 512),
                                  stride=train_kwargs.get("stride", 255))
        device = next(model.parameters()).device.type
        by_name[name]["encoder"] = {**metrics(scores, labels), "base_model": base_model,
                                    "epochs": train_kwargs.get("epochs", 1),
                                    "scored_with": f"PyTorch on {device.upper()}, before int8 quantisation"}
        print(name, "encoder", by_name[name]["encoder"], flush=True)
        if pg:
            pg_model, pg_tok, attack_index = pg
            pg_scores = torch_score_rows(pg_model, pg_tok, test_rows, max_length=512, stride=255, attack_index=attack_index)
            by_name[name]["promptguard"] = {**metrics(pg_scores, labels), "model": prompt_guard}
            print(name, "promptguard", by_name[name]["promptguard"], flush=True)
        del model
    return results


def _load_prompt_guard(model_id: str):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(model_id)
    tok.model_max_length = 10**9
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.to("cuda" if torch.cuda.is_available() else "cpu")
    labels = {i: str(l).lower() for i, l in model.config.id2label.items()}
    attack = next((i for i, l in labels.items() if "malicious" in l or "injection" in l or "jailbreak" in l), max(labels))
    return model, tok, attack


def load_base(base_model: str):
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    tokenizer.model_max_length = 10**9  # texts are windowed, never truncated

    def make_model():
        return AutoModelForSequenceClassification.from_pretrained(base_model, num_labels=2, attn_implementation="sdpa")

    return tokenizer, make_model


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=Path("ml/.cache/dataset.jsonl"))
    ap.add_argument("--results", type=Path, default=Path("docs/benchmarks"))
    ap.add_argument("--base-model", default=DEFAULT_BASE)
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--prompt-guard", default=None, help="Hugging Face id of Prompt Guard 2 (gated: accept its licence first)")
    args = ap.parse_args()

    rows = read_jsonl(args.dataset)
    results = json.loads((args.results / "results.json").read_text(encoding="utf-8"))
    tokenizer, make_model = load_base(args.base_model)
    kwargs = dict(epochs=args.epochs, lr=args.lr, batch_size=args.batch_size, max_length=512, stride=255)
    run(rows, results, make_model, tokenizer, train_kwargs=kwargs, base_model=args.base_model, prompt_guard=args.prompt_guard)
    write_report(results, args.results)
    print(f"updated {args.results / 'results.json'} and RESULTS.md")


if __name__ == "__main__":
    main()
