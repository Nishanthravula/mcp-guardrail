"""Write a model directory the proxy can load (format: MCPG-DD-002 section 4)."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

OPSET = 17


def export(model, tokenizer, out_dir, *, name: str, base_model: str, max_length: int, stride: int,
           thresholds: dict, data: dict, extra: dict | None = None) -> dict:
    """Export to ONNX, quantise weights to int8, and write the four files."""
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    model = model.eval().to("cpu").float()
    ids = torch.tensor([[tokenizer.cls_token_id, 10, 11, 12, tokenizer.sep_token_id]] * 2)
    mask = torch.ones_like(ids)
    with tempfile.TemporaryDirectory() as tmp:
        fp32 = Path(tmp) / "model-fp32.onnx"
        # The TorchScript exporter: the dynamo exporter's graph fails ONNX
        # Runtime's shape inference after quantisation for ModernBERT.
        torch.onnx.export(
            model, (), str(fp32), kwargs={"input_ids": ids, "attention_mask": mask},
            input_names=["input_ids", "attention_mask"], output_names=["logits"], opset_version=OPSET,
            dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"}, "logits": {0: "batch"}},
            dynamo=False,
        )
        quantize_dynamic(str(fp32), str(out / "model.onnx"), weight_type=QuantType.QInt8)
        tokenizer.save_pretrained(tmp)
        for f in ("tokenizer.json", "tokenizer_config.json"):
            shutil.copyfile(Path(tmp) / f, out / f)
    meta = {
        "format": 1,
        "kind": "encoder",
        "name": name,
        "baseModel": base_model,
        "maxLength": max_length,
        "stride": stride,
        "clsId": tokenizer.cls_token_id,
        "sepId": tokenizer.sep_token_id,
        "padId": tokenizer.pad_token_id,
        "thresholds": {k: float(v) for k, v in thresholds.items()},
        "sha256": hashlib.sha256((out / "model.onnx").read_bytes()).hexdigest(),
        "data": data,
        **(extra or {}),
    }
    (out / "guardrail.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta
