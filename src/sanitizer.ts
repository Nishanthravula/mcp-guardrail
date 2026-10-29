import {
  DEFAULT_RULES,
  DetectionRule,
  isPlaceholderValue,
  isSensitiveKey,
} from "./patterns.js";

export interface SanitizerOptions {
  /** Rules to apply. Defaults to DEFAULT_RULES. */
  rules?: DetectionRule[];
  /** Rule ids to disable. Use "sensitive-key" to turn off the key-aware walk. */
  disable?: string[];
  /** Extra user-supplied rules, applied after built-ins. */
  extraRules?: DetectionRule[];
  /** Only apply rules of these categories. Default: all. */
  categories?: DetectionRule["category"][];
  /**
   * Max characters allowed for any single string value in the payload.
   * Longer strings are truncated with a marker, AFTER redaction, so a cut
   * can never leave part of a secret behind. 0 disables. Default 0.
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

type Hits = Map<string, { label: string; count: number }>;

export const SENSITIVE_KEY_RULE = { id: "sensitive-key", label: "SECRET" } as const;

export class Sanitizer {
  private rules: DetectionRule[];
  private keyAware: boolean;
  private opts: SanitizerOptions;

  constructor(options: SanitizerOptions = {}) {
    const disabled = new Set(options.disable ?? []);
    const cats = options.categories ? new Set(options.categories) : null;
    this.rules = [...(options.rules ?? DEFAULT_RULES), ...(options.extraRules ?? [])]
      .filter((r) => !disabled.has(r.id))
      .filter((r) => !cats || cats.has(r.category));
    for (const r of this.rules) {
      if (!r.pattern.global) throw new Error(`rule ${r.id}: pattern needs the g flag`);
      if (r.group !== undefined && !r.pattern.hasIndices)
        throw new Error(`rule ${r.id}: pattern needs the d flag to use group`);
    }
    this.keyAware = !disabled.has(SENSITIVE_KEY_RULE.id) && (!cats || cats.has("secret"));
    this.opts = options;
  }

  private placeholder(label: string): string {
    return (this.opts.placeholder ?? ((l: string) => `[REDACTED:${l}]`))(label);
  }

  private record(hits: Hits, ruleId: string, label: string): void {
    const entry = hits.get(ruleId) ?? { label, count: 0 };
    entry.count++;
    hits.set(ruleId, entry);
    this.opts.onRedact?.({ ruleId, label });
  }

  sanitizeString(input: string): { output: string; hits: Hits } {
    const hits: Hits = new Map();

    // Collect all matches against the ORIGINAL string, so one rule's
    // placeholder can never be re-matched by another rule (no cascading).
    interface Range {
      start: number;
      end: number;
      ruleId: string;
      label: string;
      order: number;
    }
    const ranges: Range[] = [];

    this.rules.forEach((rule, order) => {
      if (rule.quickCheck && !rule.quickCheck(input)) return;
      rule.pattern.lastIndex = 0;
      for (const m of input.matchAll(rule.pattern)) {
        if (m.index === undefined) continue;
        let start = m.index;
        let end = m.index + m[0].length;
        let text = m[0];
        if (rule.group !== undefined) {
          const span = m.indices?.[rule.group];
          if (!span) continue;
          [start, end] = span;
          text = input.slice(start, end);
        }
        if (text.length === 0) continue;
        if (rule.validate && !rule.validate(text, { match: m[0], input, index: start })) continue;
        ranges.push({ start, end, ruleId: rule.id, label: rule.label, order });
      }
    });

    if (ranges.length === 0) return { output: input, hits };

    // Resolve overlaps: earliest start wins; at the same start the longer
    // match wins; on a tie the earlier (more specific) rule wins.
    ranges.sort((a, b) => a.start - b.start || b.end - a.end || a.order - b.order);
    const accepted: Range[] = [];
    for (const r of ranges) {
      const last = accepted[accepted.length - 1];
      if (last && r.start < last.end) continue;
      accepted.push(r);
    }

    let output = "";
    let cursor = 0;
    for (const r of accepted) {
      output += input.slice(cursor, r.start) + this.placeholder(r.label);
      cursor = r.end;
      this.record(hits, r.ruleId, r.label);
    }
    output += input.slice(cursor);
    return { output, hits };
  }

  /**
   * Deep-sanitize any JSON-serializable value. Strings are scanned and
   * redacted; objects and arrays are walked recursively; a string stored
   * under a sensitive key (password, api_key, accessToken, ...) is redacted
   * whole. Non-strings pass through untouched.
   */
  sanitize<T>(value: T): SanitizeResult<T> {
    const totals: Hits = new Map();
    let truncated = 0;
    const max = this.opts.maxStringLength ?? 0;

    const merge = (hits: Hits) => {
      for (const [id, h] of hits) {
        const t = totals.get(id) ?? { label: h.label, count: 0 };
        t.count += h.count;
        totals.set(id, t);
      }
    };
    const cap = (s: string): string => {
      if (max > 0 && s.length > max) {
        truncated++;
        return s.slice(0, max) + `…[TRUNCATED:${s.length - max} chars]`;
      }
      return s;
    };

    const walk = (v: unknown, key?: string): unknown => {
      if (typeof v === "string") {
        if (this.keyAware && key !== undefined && isSensitiveKey(key) && !isPlaceholderValue(v)) {
          this.record(totals, SENSITIVE_KEY_RULE.id, SENSITIVE_KEY_RULE.label);
          return this.placeholder(SENSITIVE_KEY_RULE.label);
        }
        const { output, hits } = this.sanitizeString(v);
        merge(hits);
        return cap(output);
      }
      if (Array.isArray(v)) return v.map((x) => walk(x));
      if (v !== null && typeof v === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          out[k] = walk(val, k);
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
export type { DetectionRule, MatchContext } from "./patterns.js";
