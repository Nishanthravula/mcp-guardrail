/**
 * Prompt-injection detector for tool results.
 *
 * A small linear model over hashed n-grams, run on overlapping windows of the
 * normalised text. No dependencies, and time linear in the input length.
 * It is probabilistic: see docs/injection-detection.md for what it misses.
 */
import { forEachFeature, N_FEATURES, windows } from "./featurize.js";
import { loadLinearModel, type LinearModel } from "./linear.js";
import { normalize } from "./normalize.js";

/** Longest item scored whole, in UTF-16 code units. Longer items are scored at both ends. */
export const MAX_ITEM_CHARS = 1_048_576;

export interface InjectionResult {
  /** Highest window probability, 0 to 1. */
  score: number;
  flagged: boolean;
  /** Byte offset, in the normalised text, of the highest-scoring window. */
  windowStart: number;
  /** True when the item exceeded the size cap and only its two ends were scored. */
  truncated: boolean;
}

export interface InjectionDetectorOptions {
  /** Flag items scoring at or above this value. Defaults to the model's own threshold. */
  threshold?: number;
  /** Directory holding the model files. Defaults to the one shipped with the package. */
  modelDir?: string;
}

export class InjectionDetector {
  readonly threshold: number;
  readonly modelName: string;
  private readonly model: LinearModel;
  private readonly encoder = new TextEncoder();
  // Marks which features the current window has already counted.
  private readonly stamp = new Uint32Array(N_FEATURES);
  private generation = 0;

  constructor(opts: InjectionDetectorOptions = {}) {
    this.model = loadLinearModel(opts.modelDir);
    this.modelName = this.model.name;
    const threshold = opts.threshold ?? this.model.thresholds.default;
    if (!(threshold > 0 && threshold < 1)) {
      throw new RangeError(`injection threshold must be between 0 and 1, got ${threshold}`);
    }
    this.threshold = threshold;
  }

  score(text: string): InjectionResult {
    const truncated = text.length > MAX_ITEM_CHARS;
    if (truncated) {
      const half = MAX_ITEM_CHARS / 2;
      text = text.slice(0, half) + " " + text.slice(text.length - half);
    }
    const bytes = this.encoder.encode(normalize(text));
    let score = 0;
    let windowStart = 0;
    for (const [start, end] of windows(bytes.length)) {
      const p = this.scoreWindow(bytes, start, end);
      if (p > score) {
        score = p;
        windowStart = start;
      }
    }
    return { score, flagged: score >= this.threshold, windowStart, truncated };
  }

  private scoreWindow(bytes: Uint8Array, start: number, end: number): number {
    if (++this.generation === 0xffffffff) {
      this.stamp.fill(0);
      this.generation = 1;
    }
    const { stamp, generation } = this;
    const weights = this.model.weights;
    let sum = 0;
    let active = 0;
    forEachFeature(bytes, start, end, (i) => {
      if (stamp[i] !== generation) {
        stamp[i] = generation;
        sum += weights[i];
        active++;
      }
    });
    if (active === 0) return 0;
    const s = this.model.bias + (this.model.scale * sum) / Math.sqrt(active);
    return 1 / (1 + Math.exp(-s));
  }
}
