"""Fine-tune a sequence classifier on token windows."""

from __future__ import annotations

import math
import random

import numpy as np

from ml.encoder.windows import label_windows

MAX_NEGATIVE_WINDOWS = 8


def build_examples(rows, tokenizer, max_length: int, stride: int, max_negative_windows: int = MAX_NEGATIVE_WINDOWS):
    """(ids, label) pairs; at most ``max_negative_windows`` evenly spaced benign windows per row."""
    out = []
    for row in rows:
        windows = [(ids, y) for ids, y in label_windows(row, tokenizer, max_length, stride) if y is not None]
        neg = [w for w in windows if w[1] == 0]
        if len(neg) > max_negative_windows:
            keep = set(np.linspace(0, len(neg) - 1, max_negative_windows).round().astype(int).tolist())
            neg = [w for i, w in enumerate(neg) if i in keep]
        out.extend([w for w in windows if w[1] == 1] + neg)
    return out


def _batches(examples, batch_size: int, rng: random.Random):
    """Shuffle, then sort within chunks by length so batches waste little padding."""
    order = list(range(len(examples)))
    rng.shuffle(order)
    chunk = batch_size * 50
    batches = []
    for c in range(0, len(order), chunk):
        part = sorted(order[c : c + chunk], key=lambda i: len(examples[i][0]))
        batches += [part[i : i + batch_size] for i in range(0, len(part), batch_size)]
    rng.shuffle(batches)
    return batches


def pad_batch(seqs, pad_id: int):
    import torch

    width = max(len(s) for s in seqs)
    ids = torch.full((len(seqs), width), pad_id, dtype=torch.long)
    mask = torch.zeros((len(seqs), width), dtype=torch.long)
    for i, s in enumerate(seqs):
        ids[i, : len(s)] = torch.tensor(s)
        mask[i, : len(s)] = 1
    return ids, mask


def train(rows, tokenizer, model, *, epochs: int = 1, lr: float = 2e-5, batch_size: int = 16, max_length: int = 512,
          stride: int = 255, max_negative_windows: int = MAX_NEGATIVE_WINDOWS, seed: int = 0, device: str | None = None,
          log_every: int = 200):
    """Fine-tune ``model`` in place and return it (in eval mode).

    Class-weighted cross-entropy, AdamW with linear warm-up and decay, mixed
    precision on GPU. Deterministic on CPU for a fixed seed.
    """
    import torch

    torch.manual_seed(seed)
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    examples = build_examples(rows, tokenizer, max_length, stride, max_negative_windows)
    labels = np.array([y for _, y in examples])
    pos = max(int(labels.sum()), 1)
    neg = max(len(labels) - pos, 1)
    weight = torch.tensor([len(labels) / (2 * neg), len(labels) / (2 * pos)], dtype=torch.float32, device=device)

    model.to(device).train()
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    rng = random.Random(seed)
    steps = epochs * math.ceil(len(examples) / batch_size)
    warmup = max(1, steps // 20)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min((s + 1) / warmup, max(0.0, (steps - s) / max(1, steps - warmup)))
    )
    use_amp = device == "cuda"
    amp_dtype = torch.bfloat16 if use_amp and torch.cuda.is_bf16_supported() else torch.float16
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp and amp_dtype == torch.float16)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weight)
    step = 0
    for epoch in range(epochs):
        for batch in _batches(examples, batch_size, rng):
            ids, mask = pad_batch([examples[i][0] for i in batch], tokenizer.pad_token_id)
            y = torch.tensor([examples[i][1] for i in batch], device=device)
            with torch.autocast(device_type="cuda", dtype=amp_dtype, enabled=use_amp):
                logits = model(input_ids=ids.to(device), attention_mask=mask.to(device)).logits
            loss = loss_fn(logits.float(), y)
            opt.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt)
            scaler.update()
            sched.step()
            step += 1
            if log_every and step % log_every == 0:
                print(f"epoch {epoch + 1} step {step}/{steps} loss {loss.item():.4f}", flush=True)
    return model.eval()
