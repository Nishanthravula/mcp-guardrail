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
   * Values that are never redacted, compared after trimming (exact match).
   * E.g. your own support address, a test card number, a known-safe IP.
   */
  allow?: string[];
  /** Patterns that, if they match the WHOLE detected value, keep it. */
  allowPatterns?: RegExp[];
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
  /**
   * Optional one-way fingerprint of each redacted value (e.g. a salted
   * HMAC), included in `details`. Lets audit logs tell distinct secrets
   * apart without ever storing them. Never return the value itself.
   */
  fingerprint?: (value: string) => string;
}

/** One redaction, without its value. */
export interface RedactionDetail {
  ruleId: string;
  label: string;
  /** JSON path of the string it was found in, e.g. `result.content[0].text`. */
  path: string;
  fingerprint?: string;
}

export interface SanitizeResult<T> {
  value: T;
  redactions: { ruleId: string; label: string; count: number }[];
  /** Per-redaction details (capped at 200 per call). */
  details: RedactionDetail[];
  truncated: number;
}

/** A detected span in a string. */
export interface Finding {
  start: number;
  end: number;
  ruleId: string;
  label: string;
  category: DetectionRule["category"];
}

type Hits = Map<string, { label: string; count: number }>;

export const SENSITIVE_KEY_RULE = { id: "sensitive-key", label: "SECRET" } as const;

const MAX_DETAILS = 200;

export class Sanitizer {
  private rules: DetectionRule[];
  private keyAware: boolean;
  private opts: SanitizerOptions;
  private allow: Set<string>;
  private allowPatterns: RegExp[];

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
    this.allow = new Set((options.allow ?? []).map((v) => v.trim()).filter(Boolean));
    // Anchor so an allow pattern must cover the whole value, not just part of it.
    this.allowPatterns = (options.allowPatterns ?? []).map(
      (p) => new RegExp(`^(?:${p.source})$`, p.flags.replace(/[gyd]/g, "")),
    );
    this.opts = options;
  }

  /** The ids of the active rules, in order. */
  get ruleIds(): string[] {
    return this.rules.map((r) => r.id);
  }

  private placeholder(label: string): string {
    return (this.opts.placeholder ?? ((l: string) => `[REDACTED:${l}]`))(label);
  }

  private isAllowed(value: string): boolean {
    if (this.allow.size === 0 && this.allowPatterns.length === 0) return false;
    const v = value.trim();
    return this.allow.has(v) || this.allowPatterns.some((p) => p.test(v));
  }

  /**
   * Find every span that would be redacted, after overlap resolution and
   * allowlists. Spans are sorted and never overlap.
   */
  findings(input: string): Finding[] {
    interface Range extends Finding {
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
        if (this.isAllowed(text)) continue;
        ranges.push({ start, end, ruleId: rule.id, label: rule.label, category: rule.category, order });
      }
    });
    if (ranges.length === 0) return [];

    // Earliest start wins; at the same start the longer match wins; on a tie
    // the earlier (more specific) rule wins.
    ranges.sort((a, b) => a.start - b.start || b.end - a.end || a.order - b.order);
    const accepted: Finding[] = [];
    let lastEnd = -1;
    for (const r of ranges) {
      if (r.start < lastEnd) continue;
      accepted.push({ start: r.start, end: r.end, ruleId: r.ruleId, label: r.label, category: r.category });
      lastEnd = r.end;
    }
    return accepted;
  }

  sanitizeString(input: string): { output: string; hits: Hits } {
    return this.redactString(input, new Map(), null, "");
  }

  private redactString(
    input: string,
    hits: Hits,
    details: RedactionDetail[] | null,
    path: string,
  ): { output: string; hits: Hits } {
    // All matches are found against the ORIGINAL string, so one rule's
    // placeholder can never be re-matched by another rule (no cascading).
    const found = this.findings(input);
    if (found.length === 0) return { output: input, hits };
    let output = "";
    let cursor = 0;
    for (const f of found) {
      output += input.slice(cursor, f.start) + this.placeholder(f.label);
      cursor = f.end;
      this.record(hits, details, f.ruleId, f.label, path, () => input.slice(f.start, f.end));
    }
    output += input.slice(cursor);
    return { output, hits };
  }

  private record(
    hits: Hits,
    details: RedactionDetail[] | null,
    ruleId: string,
    label: string,
    path: string,
    value: () => string,
  ): void {
    const entry = hits.get(ruleId) ?? { label, count: 0 };
    entry.count++;
    hits.set(ruleId, entry);
    this.opts.onRedact?.({ ruleId, label });
    if (details && details.length < MAX_DETAILS) {
      const d: RedactionDetail = { ruleId, label, path };
      if (this.opts.fingerprint) d.fingerprint = this.opts.fingerprint(value());
      details.push(d);
    }
  }

  /**
   * Deep-sanitize any JSON-serializable value. Strings are scanned and
   * redacted; objects and arrays are walked recursively; a string stored
   * under a sensitive key (password, api_key, accessToken, ...) is redacted
   * whole. Non-strings pass through untouched.
   */
  sanitize<T>(value: T): SanitizeResult<T> {
    const totals: Hits = new Map();
    const details: RedactionDetail[] = [];
    let truncated = 0;
    const max = this.opts.maxStringLength ?? 0;

    const cap = (s: string): string => {
      if (max > 0 && s.length > max) {
        truncated++;
        return s.slice(0, max) + `…[TRUNCATED:${s.length - max} chars]`;
      }
      return s;
    };
    const keyPath = (base: string, k: string) =>
      /^[A-Za-z_$][\w$]*$/.test(k) ? (base ? `${base}.${k}` : k) : `${base}[${JSON.stringify(k)}]`;

    const walk = (v: unknown, path: string, key?: string): unknown => {
      if (typeof v === "string") {
        if (
          this.keyAware &&
          key !== undefined &&
          isSensitiveKey(key) &&
          !isPlaceholderValue(v) &&
          !this.isAllowed(v)
        ) {
          this.record(totals, details, SENSITIVE_KEY_RULE.id, SENSITIVE_KEY_RULE.label, path, () => v);
          return this.placeholder(SENSITIVE_KEY_RULE.label);
        }
        return cap(this.redactString(v, totals, details, path).output);
      }
      if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}[${i}]`));
      if (v !== null && typeof v === "object") {
        const out: Record<string, unknown> = {};
        for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
          out[k] = walk(val, keyPath(path, k), k);
        }
        return out;
      }
      return v;
    };

    const result = walk(value, "") as T;
    return {
      value: result,
      redactions: [...totals.entries()].map(([ruleId, h]) => ({
        ruleId,
        label: h.label,
        count: h.count,
      })),
      details,
      truncated,
    };
  }
}

export { DEFAULT_RULES } from "./patterns.js";
export type { DetectionRule, MatchContext } from "./patterns.js";
