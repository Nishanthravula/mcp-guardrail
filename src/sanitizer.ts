import { DEFAULT_RULES, DetectionRule } from "./patterns.js";

export interface SanitizerOptions {
  /** Rules to apply. Defaults to DEFAULT_RULES. */
  rules?: DetectionRule[];
  /** Rule ids to disable. */
  disable?: string[];
  /** Extra user-supplied rules, applied after built-ins. */
  extraRules?: DetectionRule[];
  /**
   * Max characters allowed for any single string value in the payload.
   * Longer strings are truncated with a marker. 0 disables. Default 0.
   */
  maxStringLength?: number;
  /** Placeholder format. Default: (label) => `[REDACTED:${label}]` */
  placeholder?: (label: string) => string;
  /** Called once per redaction with rule id and label (never the value). */
  onRedact?: (info: { ruleId: string; label: string }) => void;
}

export interface SanitizeResult<T> {
  value: T;
  redactions: { ruleId: string; label: string; count: number }[];
  truncated: number;
}

export class Sanitizer {
  private rules: DetectionRule[];
  private opts: Required<Pick<SanitizerOptions, "maxStringLength">> &
    SanitizerOptions;

  constructor(options: SanitizerOptions = {}) {
    const disabled = new Set(options.disable ?? []);
    this.rules = [
      ...(options.rules ?? DEFAULT_RULES),
      ...(options.extraRules ?? []),
    ].filter((r) => !disabled.has(r.id));
    this.opts = { maxStringLength: 0, ...options };
  }

  sanitizeString(input: string): { output: string; hits: Map<string, { label: string; count: number }> } {
    const hits = new Map<string, { label: string; count: number }>();
    const placeholder =
      this.opts.placeholder ?? ((label: string) => `[REDACTED:${label}]`);

    // Collect all matches against the ORIGINAL string, so one rule's
    // placeholder can never be re-matched by another rule (no cascading).
    interface Range {
      start: number;
      end: number;
      ruleId: string;
      label: string;
    }
    const ranges: Range[] = [];

    for (const rule of this.rules) {
      rule.pattern.lastIndex = 0;
      for (const m of input.matchAll(rule.pattern)) {
        const text = m[0];
        if (m.index === undefined) continue;
        if (rule.validate && !rule.validate(text)) continue;
        ranges.push({
          start: m.index,
          end: m.index + text.length,
          ruleId: rule.id,
          label: rule.label,
        });
      }
    }

    if (ranges.length === 0) return { output: input, hits };

    // Resolve overlaps: earlier (more specific) rules win; among the same
    // rule, longer matches win.
    ranges.sort((a, b) => a.start - b.start || b.end - a.end);
    const accepted: Range[] = [];
    for (const r of ranges) {
      const last = accepted[accepted.length - 1];
      if (last && r.start < last.end) continue; // overlaps an accepted range
      accepted.push(r);
    }

    let output = "";
    let cursor = 0;
    for (const r of accepted) {
      output += input.slice(cursor, r.start) + placeholder(r.label);
      cursor = r.end;
      const entry = hits.get(r.ruleId) ?? { label: r.label, count: 0 };
      entry.count++;
      hits.set(r.ruleId, entry);
      this.opts.onRedact?.({ ruleId: r.ruleId, label: r.label });
    }
    output += input.slice(cursor);

    return { output, hits };
  }

  /**
   * Deep-sanitize any JSON-serializable value. Strings are scanned and
   * redacted; objects and arrays are walked recursively. Non-strings pass
   * through untouched.
   */
  sanitize<T>(value: T): SanitizeResult<T> {
    const totals = new Map<string, { label: string; count: number }>();
    let truncated = 0;
    const max = this.opts.maxStringLength ?? 0;

    const walk = (v: unknown): unknown => {
      if (typeof v === "string") {
        let s = v;
        if (max > 0 && s.length > max) {
          s = s.slice(0, max) + `…[TRUNCATED:${v.length - max} chars]`;
          truncated++;
        }
        const { output, hits } = this.sanitizeString(s);
        for (const [id, h] of hits) {
          const t = totals.get(id) ?? { label: h.label, count: 0 };
          t.count += h.count;
          totals.set(id, t);
        }
        return output;
      }
      if (Array.isArray(v)) return v.map(walk);
      if (v !== null && typeof v === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          out[k] = walk(val);
        }
        return out;
      }
      return v;
    };

    const result = walk(value) as T;
    return {
      value: result,
      redactions: [...totals.entries()].map(([ruleId, h]) => ({
        ruleId,
        label: h.label,
        count: h.count,
      })),
      truncated,
    };
  }
}

export { DEFAULT_RULES } from "./patterns.js";
export type { DetectionRule } from "./patterns.js";
