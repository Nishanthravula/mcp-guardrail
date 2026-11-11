from ml.data import synthetic
from ml.features import normalize


def test_generation_is_deterministic():
    assert synthetic.generate() == synthetic.generate()


def test_counts_and_labels():
    rows = synthetic.generate()
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    assert len(pos) >= 3000 and len(neg) >= 2000
    assert all(r["source"] == "synthetic" for r in rows)
    assert all(r["attack"] == "synthetic" for r in pos) and all(r["attack"] == "" for r in neg)


def test_attack_span_covers_the_injected_sentence_only():
    rows = [r for r in synthetic.generate() if r["label"] == 1]
    for r in rows[:300]:
        (start, end), = r["spans"]
        data = r["text"].encode()
        assert 0 <= start < end <= len(data)
        inside = data[start:end].decode()
        assert inside == inside.strip() and len(inside) >= 20
    embedded = [r for r in rows if r["spans"][0][0] > 0]
    assert len(embedded) > len(rows) // 3  # many attacks sit inside benign carrier text


def test_text_is_already_normalised():
    assert all(r["text"] == normalize(r["text"]) for r in synthetic.generate()[:500])


def test_groups_allow_holding_out_whole_openers():
    rows = synthetic.generate()
    pos_groups = {r["group"] for r in rows if r["label"] == 1}
    assert len(pos_groups) == len(synthetic.OPENERS)
    assert len({r["group"] for r in rows if r["label"] == 0}) >= 10


def test_benign_rows_contain_no_generated_attack():
    rows = synthetic.generate()
    openers = [normalize(o) for o in synthetic.OPENERS]
    benign_text = " ".join(r["text"] for r in rows if r["label"] == 0)
    assert not any(o in benign_text for o in openers)
