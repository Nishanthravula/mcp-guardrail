/**
 * Optional transformer detector: a fine-tuned encoder exported to ONNX.
 *
 * Needs two optional packages, `onnxruntime-node` and
 * `@huggingface/tokenizers`, which are loaded only when a model directory is
 * configured. Windows, batching and probabilities mirror ml/encoder/score.py;
 * tests/fixtures/encoder-tiny/golden.json holds the two together.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import type { InferenceSession, Tensor } from "onnxruntime-node";
import type { Tokenizer } from "@huggingface/tokenizers";
import { MAX_ITEM_CHARS, type InjectionResult } from "./detector.js";
import { normalize } from "./normalize.js";
import type { Scorer } from "./scorer.js";

const BATCH = 8;
const PEERS = "npm install onnxruntime-node @huggingface/tokenizers";

interface EncoderMeta {
  format: 1;
  kind: "encoder";
  name: string;
  maxLength: number;
  stride: number;
  clsId: number;
  sepId: number;
  padId: number;
  thresholds: { fpr1: number; fpr01: number; default: number };
  sha256: string;
}

/** Token index ranges covering `n` tokens; `maxLength` counts the two special tokens. */
export function tokenWindows(n: number, maxLength: number, stride: number): [number, number][] {
  const size = maxLength - 2;
  if (n <= 0) return [];
  if (n <= size) return [[0, n]];
  const out: [number, number][] = [];
  for (let s = 0; s + size <= n; s += stride) out.push([s, s + size]);
  if (out[out.length - 1][1] < n) out.push([n - size, n]);
  return out;
}

function fail(dir: string, why: string): never {
  throw new Error(`mcp-guardrail: injection model in ${dir} ${why}`);
}

const isInt = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0;
const isProbability = (v: unknown): v is number => typeof v === "number" && v > 0 && v < 1;

function readMeta(dir: string): EncoderMeta {
  let meta: Record<string, unknown>;
  try {
    meta = JSON.parse(fs.readFileSync(path.join(dir, "guardrail.json"), "utf8"));
  } catch (err) {
    return fail(dir, `could not be read: ${(err as Error).message}`);
  }
  if (meta?.format !== 1) fail(dir, `has unsupported format ${JSON.stringify(meta?.format)}; this version reads format 1`);
  if (meta.kind !== "encoder") fail(dir, `is not a transformer model (kind ${JSON.stringify(meta.kind)})`);
  const t = meta.thresholds as Record<string, unknown> | undefined;
  const ok =
    typeof meta.name === "string" && typeof meta.sha256 === "string" &&
    isInt(meta.maxLength) && (meta.maxLength as number) > 2 && isInt(meta.stride) && (meta.stride as number) > 0 &&
    isInt(meta.clsId) && isInt(meta.sepId) && isInt(meta.padId) &&
    !!t && isProbability(t.fpr1) && isProbability(t.fpr01) && isProbability(t.default);
  if (!ok) fail(dir, "has invalid metadata in guardrail.json");
  return meta as unknown as EncoderMeta;
}

function loadPeers(): { ort: typeof import("onnxruntime-node"); Tokenizer: typeof Tokenizer } {
  const require = createRequire(import.meta.url);
  try {
    return {
      ort: require("onnxruntime-node"),
      Tokenizer: (require("@huggingface/tokenizers") as { Tokenizer: typeof Tokenizer }).Tokenizer,
    };
  } catch (err) {
    throw new Error(
      `mcp-guardrail: injection model needs two optional packages that are not installed (${(err as Error).message.split("\n")[0]}). ` +
        `Install them next to mcp-guardrail: ${PEERS}`,
    );
  }
}

export class EncoderDetector implements Scorer {
  readonly threshold: number;
  readonly modelName: string;

  private constructor(
    private readonly meta: EncoderMeta,
    private readonly tokenizer: Tokenizer,
    private readonly session: InferenceSession,
    private readonly Tensor: typeof import("onnxruntime-node").Tensor,
    threshold: number,
  ) {
    this.threshold = threshold;
    this.modelName = meta.name;
  }

  /** Load a model directory (model.onnx, tokenizer.json, tokenizer_config.json, guardrail.json). */
  static async load(dir: string, opts: { threshold?: number } = {}): Promise<EncoderDetector> {
    const meta = readMeta(dir);
    const threshold = opts.threshold ?? meta.thresholds.default;
    if (!(threshold > 0 && threshold < 1)) {
      throw new RangeError(`injection threshold must be between 0 and 1, got ${threshold}`);
    }
    let model: Buffer;
    let tokenizerJson: object;
    let tokenizerConfig: object;
    try {
      model = fs.readFileSync(path.join(dir, "model.onnx"));
      tokenizerJson = JSON.parse(fs.readFileSync(path.join(dir, "tokenizer.json"), "utf8"));
      tokenizerConfig = JSON.parse(fs.readFileSync(path.join(dir, "tokenizer_config.json"), "utf8"));
    } catch (err) {
      return fail(dir, `is incomplete: ${(err as Error).message}`);
    }
    if (createHash("sha256").update(model).digest("hex") !== meta.sha256) {
      fail(dir, "failed its checksum; model.onnx is corrupted or was modified");
    }
    const { ort, Tokenizer } = loadPeers();
    const session = await ort.InferenceSession.create(model);
    return new EncoderDetector(meta, new Tokenizer(tokenizerJson, tokenizerConfig), session, ort.Tensor, threshold);
  }

  /** Token ids of the normalised text, without special tokens (exposed for parity tests). */
  tokenIds(text: string): number[] {
    if (text.length > MAX_ITEM_CHARS) {
      const half = MAX_ITEM_CHARS / 2;
      text = text.slice(0, half) + " " + text.slice(text.length - half);
    }
    const norm = normalize(text);
    return norm ? this.tokenizer.encode(norm, { add_special_tokens: false }).ids : [];
  }

  /** `windowStart` is the token index where the highest-scoring window begins. */
  async score(text: string): Promise<InjectionResult> {
    const truncated = text.length > MAX_ITEM_CHARS;
    const ids = this.tokenIds(text);
    const { maxLength, stride, clsId, sepId, padId } = this.meta;
    const windows = tokenWindows(ids.length, maxLength, stride);
    let score = 0;
    let windowStart = 0;
    for (let b = 0; b < windows.length; b += BATCH) {
      const chunk = windows.slice(b, b + BATCH);
      const width = Math.max(...chunk.map(([s, e]) => e - s)) + 2;
      const input = new BigInt64Array(chunk.length * width).fill(BigInt(padId));
      const mask = new BigInt64Array(chunk.length * width);
      chunk.forEach(([s, e], i) => {
        const row = [clsId, ...ids.slice(s, e), sepId];
        row.forEach((id, j) => {
          input[i * width + j] = BigInt(id);
          mask[i * width + j] = 1n;
        });
      });
      const dims = [chunk.length, width];
      const out = await this.session.run({
        input_ids: new this.Tensor("int64", input, dims),
        attention_mask: new this.Tensor("int64", mask, dims),
      });
      const logits = (out.logits as Tensor).data as Float32Array;
      chunk.forEach(([s], i) => {
        const a = logits[i * 2];
        const c = logits[i * 2 + 1];
        const m = Math.max(a, c);
        const p = Math.exp(c - m) / (Math.exp(a - m) + Math.exp(c - m));
        if (p > score) {
          score = p;
          windowStart = s;
        }
      });
    }
    return { score, flagged: score >= this.threshold, windowStart, truncated };
  }
}
