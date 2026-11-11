/** Loading and checking the shipped linear model. */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { N_FEATURES, STRIDE, WINDOW } from "./featurize.js";

export interface LinearModel {
  name: string;
  /** One int8 weight per hashed feature. */
  weights: Int8Array;
  scale: number;
  bias: number;
  thresholds: { fpr1: number; fpr01: number; default: number };
  sha256: string;
}

export const DEFAULT_MODEL = "injection-linear-v1";
const DEFAULT_DIR = fileURLToPath(new URL("../../models/", import.meta.url));

function fail(name: string, why: string): never {
  throw new Error(`mcp-guardrail: injection model "${name}" ${why}`);
}

const isProbability = (v: unknown): v is number => typeof v === "number" && v > 0 && v < 1;

/**
 * Read a model from `dir`. Throws rather than returning a partly valid model:
 * a detector that silently scores everything as benign is worse than none.
 */
export function loadLinearModel(dir: string = DEFAULT_DIR, name: string = DEFAULT_MODEL): LinearModel {
  let meta: Record<string, unknown>;
  let blob: Buffer;
  try {
    meta = JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), "utf8"));
    blob = fs.readFileSync(path.join(dir, `${name}.bin`));
  } catch (err) {
    return fail(name, `could not be read from ${dir}: ${(err as Error).message}`);
  }
  if (meta === null || typeof meta !== "object") fail(name, "has unreadable metadata");
  if (meta.format !== 1) fail(name, `has unsupported format ${JSON.stringify(meta.format)}; this version reads format 1`);
  if (meta.nFeatures !== N_FEATURES || meta.window !== WINDOW || meta.stride !== STRIDE) {
    fail(name, "was built with different feature settings than this version");
  }
  if (blob.length !== N_FEATURES) fail(name, `has ${blob.length} weights, expected ${N_FEATURES}`);
  const sha256 = createHash("sha256").update(blob).digest("hex");
  if (sha256 !== meta.sha256) fail(name, "failed its checksum; the weights file is corrupted or was modified");
  const t = meta.thresholds as Record<string, unknown> | undefined;
  if (typeof meta.scale !== "number" || typeof meta.bias !== "number" || !t ||
      !isProbability(t.fpr1) || !isProbability(t.fpr01) || !isProbability(t.default)) {
    fail(name, "has invalid metadata");
  }
  return {
    name: typeof meta.name === "string" ? meta.name : name,
    weights: new Int8Array(blob.buffer, blob.byteOffset, blob.length),
    scale: meta.scale as number,
    bias: meta.bias as number,
    thresholds: { fpr1: t!.fpr1 as number, fpr01: t!.fpr01 as number, default: t!.default as number },
    sha256,
  };
}
