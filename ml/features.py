"""Reference text normalisation and feature hashing for the injection detector.

The TypeScript implementation in ``src/injection/`` must reproduce this file
exactly; ``tests/fixtures/injection-golden.json`` holds the two together.
Every constant here is part of the model format: changing one means training
and shipping a new model version.
"""

from __future__ import annotations

import re
import unicodedata

import numpy as np

N_FEATURES = 1 << 18
WINDOW = 512
STRIDE = 256
BYTE_NGRAMS = (3, 4, 5)
FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193
UNIGRAM_PREFIX = 0x11
BIGRAM_PREFIX = 0x12

_TAG_BASE = 0xE0000
_DELETE = re.compile(
    "[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000E0000-\U000E007F]"
)
_SPACE = re.compile("[ \t\n\r\f\v\u00a0\u2028\u2029]+")
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}
_TAG_TO_ASCII = {cp: cp - _TAG_BASE for cp in range(0xE0020, 0xE007F)}
_TOKEN = re.compile(rb"[a-z0-9\x80-\xff]+")


def normalize(text: str) -> str:
    """Canonicalise text so trivially obfuscated variants hash the same way."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_TAG_TO_ASCII)  # invisible "tag" letters become visible ASCII
    text = _DELETE.sub("", text)
    text = text.translate(_ASCII_LOWER)
    return _SPACE.sub(" ", text).strip(" ")


def windows(n_bytes: int) -> list[tuple[int, int]]:
    """Overlapping (start, end) byte ranges covering a text of ``n_bytes``."""
    if n_bytes <= 0:
        return []
    if n_bytes <= WINDOW:
        return [(0, n_bytes)]
    out = [(s, s + WINDOW) for s in range(0, n_bytes - WINDOW + 1, STRIDE)]
    if out[-1][1] < n_bytes:
        out.append((n_bytes - WINDOW, n_bytes))
    return out


def fnv1a(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return h


def _word_features(window: bytes) -> set[int]:
    tokens = _TOKEN.findall(window)
    out = {fnv1a(bytes([UNIGRAM_PREFIX]) + t) % N_FEATURES for t in tokens}
    for a, b in zip(tokens, tokens[1:]):
        out.add(fnv1a(bytes([BIGRAM_PREFIX]) + a + b" " + b) % N_FEATURES)
    return out


def featurize(window: bytes) -> list[int]:
    """Sorted distinct feature indices of one window (plain-Python reference)."""
    out = _word_features(window)
    for n in BYTE_NGRAMS:
        prefix = bytes([n])
        for i in range(len(window) - n + 1):
            out.add(fnv1a(prefix + window[i : i + n]) % N_FEATURES)
    return sorted(out)


def featurize_fast(window: bytes) -> np.ndarray:
    """Same result as :func:`featurize`, with the byte n-grams vectorised."""
    parts = [np.fromiter(_word_features(window), dtype=np.uint32)]
    arr = np.frombuffer(window, dtype=np.uint8).astype(np.uint32)
    prime = np.uint32(FNV_PRIME)
    for n in BYTE_NGRAMS:
        m = len(arr) - n + 1
        if m <= 0:
            continue
        h = np.full(m, (FNV_OFFSET ^ n) & 0xFFFFFFFF, dtype=np.uint32) * prime
        for j in range(n):
            h = (h ^ arr[j : j + m]) * prime
        parts.append(h % np.uint32(N_FEATURES))
    return np.unique(np.concatenate(parts)).astype(np.uint32)
