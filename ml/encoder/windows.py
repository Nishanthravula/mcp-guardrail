"""Token windows for the transformer detector.

The Node scorer (src/injection/encoder.ts) cuts token ids exactly the same
way; tests/fixtures/encoder-tiny/golden.json holds the two together.
"""

from __future__ import annotations

MIN_OVERLAP_TOKENS = 16


def token_windows(n: int, max_length: int, stride: int) -> list[tuple[int, int]]:
    """Token index ranges covering ``n`` tokens. ``max_length`` counts the two special tokens."""
    size = max_length - 2
    if n <= 0:
        return []
    if n <= size:
        return [(0, n)]
    out = [(s, s + size) for s in range(0, n - size + 1, stride)]
    if out[-1][1] < n:
        out.append((n - size, n))
    return out


def wrap(ids: list[int], cls_id: int, sep_id: int) -> list[int]:
    return [cls_id, *ids, sep_id]


def _char_spans(text: str, spans) -> list[tuple[int, int]]:
    data = text.encode("utf-8")
    to_char = lambda b: len(data[:b].decode("utf-8", errors="ignore"))
    return [(to_char(s), to_char(e)) for s, e in spans]


def label_windows(row: dict, tokenizer, max_length: int, stride: int) -> list[tuple[list[int], int | None]]:
    """Wrapped token ids of every window of a row, with its training label.

    1 = holds at least ``min(16, tokens in the injection)`` tokens of an
    injection; 0 = holds none; None = holds only a little (left out of training).
    """
    enc = tokenizer(row["text"], add_special_tokens=False, return_offsets_mapping=True)
    ids, offsets = enc["input_ids"], enc["offset_mapping"]
    spans = _char_spans(row["text"], row["spans"]) if row["label"] else []
    in_span = [[min(e, ce) > max(s, cs) for s, e in offsets] for cs, ce in spans]
    span_tokens = [sum(flags) for flags in in_span]
    cls_id, sep_id = tokenizer.cls_token_id, tokenizer.sep_token_id
    out = []
    for s, e in token_windows(len(ids), max_length, stride):
        label: int | None = 0
        for flags, total in zip(in_span, span_tokens):
            inside = sum(flags[s:e])
            if total and inside >= min(MIN_OVERLAP_TOKENS, total):
                label = 1
                break
            if inside:
                label = None
        out.append((wrap(ids[s:e], cls_id, sep_id), label))
    return out
