"""Build the training and evaluation dataset from pinned public sources.

Nothing here executes code from the downloaded repositories: they are read as
JSON and text only. Downloads go to ``ml/.cache/`` and are never committed.

    python -m ml.data.sources --out ml/.cache/dataset.jsonl
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path

from ml.features import normalize

SOURCES = {
    "agentdojo": ("https://github.com/ethz-spylab/agentdojo", "089ed468cf3ed0322acc66b0211f26d9d90dbf60"),
    "injecagent": ("https://github.com/uiuc-kang-lab/InjecAgent", "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"),
}
LOCAL_EXTENSIONS = (".md", ".json", ".ts", ".js")
LOCAL_MAX_FILES = 40
LOCAL_MAX_CHARS = 20_000
LOCAL_MAX_BYTES = 1_000_000

# Matching an injection inside a tool result has to survive YAML/JSON
# re-rendering (re-wrapped lines, doubled quotes), so both sides are compared
# on their alphanumeric characters only and mapped back to byte offsets.
_KEY_CHAR = re.compile(rb"[a-z0-9\x80-\xff]")
PREFIX_KEY_CHARS = 60
FRAGMENT_KEY_CHARS = 40

Row = dict


def _key(norm: str) -> tuple[bytes, list[int]]:
    data = norm.encode("utf-8")
    offsets = [m.start() for m in _KEY_CHAR.finditer(data)]
    return bytes(data[i] for i in offsets), offsets


def find_injection(norm: str, injection_norm: str) -> list[int] | None | bool:
    """Locate ``injection_norm`` in ``norm``.

    Returns ``[start, end]`` byte offsets when the whole injection, or at
    least its first ``PREFIX_KEY_CHARS`` characters, is present; ``False`` when
    only a fragment is present (the row is ambiguous and should be dropped);
    ``None`` when it is absent.
    """
    key, offsets = _key(norm)
    inj, _ = _key(injection_norm)
    if not inj or not key:
        return None
    at = key.find(inj)
    if at >= 0:
        return [offsets[at], offsets[at + len(inj) - 1] + 1]
    if len(inj) >= PREFIX_KEY_CHARS:
        at = key.find(inj[:PREFIX_KEY_CHARS])
        if at >= 0:
            n = PREFIX_KEY_CHARS
            while at + n < len(key) and n < len(inj) and key[at + n] == inj[n]:
                n += 1
            return [offsets[at], offsets[at + n - 1] + 1]
    if len(inj) >= FRAGMENT_KEY_CHARS:
        grams = {inj[i : i + FRAGMENT_KEY_CHARS] for i in range(len(inj) - FRAGMENT_KEY_CHARS + 1)}
        for i in range(0, len(key) - FRAGMENT_KEY_CHARS + 1, FRAGMENT_KEY_CHARS // 2):
            if key[i : i + FRAGMENT_KEY_CHARS] in grams:
                return False
    return None


def _row(norm: str, label: int, source: str, group: str, attack: str, spans: list[list[int]]) -> Row:
    return {
        "id": hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16],
        "text": norm,
        "label": label,
        "source": source,
        "group": group,
        "attack": attack,
        "spans": spans,
    }


def _tool_text(content) -> str | None:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [c.get("content") for c in content if isinstance(c, dict)]
        return "".join(p for p in parts if isinstance(p, str))
    return None


def load_agentdojo(root: Path) -> list[Row]:
    rows: list[Row] = []
    for path in sorted(Path(root).glob("runs/**/*.json")):
        try:
            run = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        if not isinstance(run, dict) or not isinstance(run.get("messages"), list):
            continue
        injections = [normalize(v) for v in (run.get("injections") or {}).values() if isinstance(v, str)]
        attack = run.get("attack_type") or ""
        suite = run.get("suite_name") or ""
        for message in run["messages"]:
            if not isinstance(message, dict) or message.get("role") != "tool":
                continue
            text = _tool_text(message.get("content"))
            norm = normalize(text) if text else ""
            if not norm:
                continue
            found = [find_injection(norm, inj) for inj in injections]
            spans = [f for f in found if isinstance(f, list)]
            if spans:
                rows.append(_row(norm, 1, "agentdojo", suite, attack, sorted(spans)))
            elif any(f is False for f in found):
                continue  # only a fragment of an injection: ambiguous, leave it out
            else:
                rows.append(_row(norm, 0, "agentdojo", suite, "", []))
    return rows


def load_injecagent(root: Path) -> list[Row]:
    data = Path(root) / "data"
    rows: list[Row] = []
    for kind in ("dh", "ds"):
        for level in ("base", "enhanced"):
            for case in json.loads((data / f"test_cases_{kind}_{level}.json").read_text(encoding="utf-8")):
                norm = normalize(case["Tool Response"])
                span = find_injection(norm, normalize(case["Attacker Instruction"]))
                if isinstance(span, list):
                    rows.append(_row(norm, 1, "injecagent", case["User Tool"], level, [span]))
    benign = json.loads((data / "attacker_simulated_responses.json").read_text(encoding="utf-8"))
    for key, value in benign.items():
        norm = normalize(value if isinstance(value, str) else json.dumps(value))
        tool = re.match(r"\((\w+)", key)
        if norm:
            rows.append(_row(norm, 0, "injecagent", tool.group(1) if tool else key, "", []))
    return rows


def _packages(node_modules: Path):
    for entry in sorted(node_modules.iterdir()):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if entry.name.startswith("@"):
            for sub in sorted(entry.iterdir()):
                if sub.is_dir():
                    yield f"{entry.name}/{sub.name}", sub
        else:
            yield entry.name, entry


def load_local(node_modules: Path) -> list[Row]:
    """Benign text files, as a filesystem MCP server would return them."""
    rows: list[Row] = []
    for name, pkg in _packages(Path(node_modules)):
        files = [
            p
            for p in sorted(pkg.rglob("*"))
            if p.suffix in LOCAL_EXTENSIONS
            and "node_modules" not in p.relative_to(pkg).parts
            and p.is_file()
            and p.stat().st_size <= LOCAL_MAX_BYTES
        ]
        files.sort(key=lambda p: (LOCAL_EXTENSIONS.index(p.suffix), str(p.relative_to(pkg))))
        for path in files[:LOCAL_MAX_FILES]:
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            norm = normalize(text[:LOCAL_MAX_CHARS])
            if norm:
                rows.append(_row(norm, 0, "local", name, "", []))
    return rows


def dedupe(rows: list[Row]) -> list[Row]:
    """One row per distinct text; a text ever seen as an attack stays an attack."""
    best: dict[str, Row] = {}
    for row in rows:
        seen = best.get(row["id"])
        if seen is None or row["label"] > seen["label"]:
            best[row["id"]] = row
    return sorted(best.values(), key=lambda r: (r["source"], r["id"]))


def fetch(cache: Path) -> dict[str, Path]:
    """Download each source at its pinned revision and verify it."""
    out: dict[str, Path] = {}
    for name, (url, revision) in SOURCES.items():
        dest = Path(cache) / name
        if not (dest / ".git").exists():
            dest.mkdir(parents=True, exist_ok=True)
            for cmd in (
                ["git", "init", "-q"],
                ["git", "remote", "add", "origin", url],
                ["git", "fetch", "-q", "--depth", "1", "origin", revision],
                ["git", "checkout", "-q", "FETCH_HEAD"],
            ):
                subprocess.run(cmd, cwd=dest, check=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=dest, check=True, capture_output=True, text=True
        ).stdout.strip()
        if head != revision:
            raise RuntimeError(f"{name}: expected revision {revision}, found {head}")
        out[name] = dest
    return out


def build(cache: Path, node_modules: Path) -> list[Row]:
    paths = fetch(cache)
    from ml.data.synthetic import generate

    return dedupe(
        load_agentdojo(paths["agentdojo"]) + load_injecagent(paths["injecagent"]) + load_local(node_modules) + generate()
    )


def read_jsonl(path: Path) -> list[Row]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cache", type=Path, default=Path("ml/.cache"))
    ap.add_argument("--node-modules", type=Path, default=Path("node_modules"))
    ap.add_argument("--out", type=Path, default=Path("ml/.cache/dataset.jsonl"))
    args = ap.parse_args()
    rows = build(args.cache, args.node_modules)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    counts = collections.Counter((r["source"], r["label"]) for r in rows)
    for (source, label), n in sorted(counts.items()):
        print(f"{source:12s} {'attack' if label else 'benign'}  {n}")
    print(f"total {len(rows)} rows -> {args.out}")


if __name__ == "__main__":
    main()
