"""Keyword baseline: a rule list of the kind a regex-only guard would ship.

The patterns are written from general knowledge of prompt-injection phrasing,
not derived from the evaluation datasets, so the comparison stays fair.
"""

from __future__ import annotations

import re

PATTERNS = [
    r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|preceding)\b.{0,30}\b(instructions?|prompts?|messages?|directions?|rules?|context)\b",
    r"\b(ignore|disregard|forget)\b (everything|all) (you|that|above|before)",
    r"\byou are now\b",
    r"\bnew (instructions?|task|rules?)\s*:",
    r"\bsystem prompt\b",
    r"\bdo not (tell|inform|notify|mention (this |it )?to) the user\b",
    r"\bwithout (telling|informing|notifying) the user\b",
    r"<\s*/?\s*(system|instructions?|im_start|admin)\s*>",
    r"\[\s*(system|inst)\s*\]",
    r"\bact as (an? )?(unrestricted|jailbroken|dan)\b",
    r"\byour (new|real|actual) (task|goal|instructions?) (is|are)\b",
    r"\bstrictly (adhere|follow)\b.{0,40}\binstructions?\b",
]
_COMPILED = [re.compile(p) for p in PATTERNS]


def regex_baseline(norm: str) -> float:
    """1.0 if any pattern matches the normalised text, else 0.0."""
    return 1.0 if any(p.search(norm) for p in _COMPILED) else 0.0
