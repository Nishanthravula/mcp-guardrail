/** What the proxy needs from an injection model, built-in or optional. */
import { InjectionDetector, type InjectionResult } from "./detector.js";

export interface Scorer {
  /** Items scoring at or above this value are flagged. */
  readonly threshold: number;
  /** Model name, recorded in audit events. */
  readonly modelName: string;
  score(text: string): InjectionResult | Promise<InjectionResult>;
}

/**
 * The scorer for a config value: `undefined` or `"builtin"` gives the
 * built-in linear model; anything else is a model directory for the optional
 * transformer detector.
 */
export async function loadScorer(model: string | undefined, threshold?: number): Promise<Scorer> {
  if (model === undefined || model === "builtin") return new InjectionDetector({ threshold });
  const { EncoderDetector } = await import("./encoder.js");
  return EncoderDetector.load(model, { threshold });
}
