/**
 * Config file support (`--config guardrail.json` or MCP_GUARDRAIL_CONFIG).
 *
 * Validation is strict on purpose: in a security tool, a typo such as
 * "dissable" must fail loudly rather than silently do nothing.
 */
import fs from "node:fs";
import path from "node:path";
import { DEFAULT_RULES, DetectionRule, shannonEntropy } from "./patterns.js";
import { SENSITIVE_KEY_RULE } from "./sanitizer.js";

export interface CustomRuleConfig {
  id: string;
  /** Placeholder label, e.g. ACME_KEY -> [REDACTED:ACME_KEY]. Default: id upper-cased. */
  label?: string;
  category?: "secret" | "pii";
  /** JavaScript regular expression source, without slashes. */
  pattern: string;
  /** Extra regex flags, e.g. "i". `g` (and `d` with group) are added for you. */
  flags?: string;
  /** Redact only this capture group, e.g. the value in NAME=value. */
  group?: number;
  /** Skip matches whose redacted text has lower Shannon entropy (bits/char). */
  minEntropy?: number;
}

export interface ToolPolicy {
  /** Forward this tool's results untouched (e.g. a tool that only returns images). */
  skip?: boolean;
  /** Rule ids to turn off for this tool's results only. */
  disable?: string[];
}

export interface GuardrailConfig {
  $schema?: string;
  /** Also block requests that would send a secret to the server (same as --both). */
  both?: boolean;
  /** Let requests containing "[REDACTED:...]" through (same as --allow-placeholders). */
  allowPlaceholders?: boolean;
  maxStringLength?: number;
  /** Rule ids to turn off everywhere. */
  disable?: string[];
  /** Only apply rules of these categories. */
  categories?: ("secret" | "pii")[];
  /** Exact values that are never redacted. */
  allow?: string[];
  /** Regexes that keep a detected value when they match all of it. */
  allowPatterns?: string[];
  /** Your own detection rules, applied after the built-ins. */
  rules?: CustomRuleConfig[];
  /** Per-tool policies, keyed by MCP tool name. */
  tools?: Record<string, ToolPolicy>;
  /** Report what would be redacted or blocked, but change nothing. */
  dryRun?: boolean;
  /** Append a JSONL audit log here (relative to the config file). */
  auditLog?: string;
  /** Suppress stderr logs. */
  quiet?: boolean;
}

export class ConfigError extends Error {}

const TOP_KEYS = new Set([
  "$schema", "both", "allowPlaceholders", "maxStringLength", "disable", "categories",
  "allow", "allowPatterns", "rules", "tools", "dryRun", "auditLog", "quiet",
]);
const RULE_KEYS = new Set(["id", "label", "category", "pattern", "flags", "group", "minEntropy"]);
const TOOL_KEYS = new Set(["skip", "disable"]);

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

function closest(word: string, options: Iterable<string>): string | null {
  let best: string | null = null;
  let bestD = 3;
  for (const o of options) {
    const d = editDistance(word.toLowerCase(), o.toLowerCase());
    if (d < bestD) [best, bestD] = [o, d];
  }
  return best;
}

function editDistance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[a.length][b.length];
}

function checkKeys(obj: Record<string, unknown>, allowed: Set<string>, where: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      const hint = closest(k, allowed);
      throw new ConfigError(`${where}: unknown key "${k}"${hint ? ` (did you mean "${hint}"?)` : ""}`);
    }
  }
}

function expect(cond: boolean, msg: string): asserts cond {
  if (!cond) throw new ConfigError(msg);
}

const isStrArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

/** Parse and validate a config object. Throws ConfigError with a precise message. */
export function validateConfig(raw: unknown, source = "config"): GuardrailConfig {
  expect(isObj(raw), `${source}: must be a JSON object`);
  checkKeys(raw, TOP_KEYS, source);
  const c = raw as GuardrailConfig;

  for (const k of ["both", "allowPlaceholders", "dryRun", "quiet"] as const)
    expect(c[k] === undefined || typeof c[k] === "boolean", `${source}: "${k}" must be true or false`);
  expect(
    c.maxStringLength === undefined || (Number.isInteger(c.maxStringLength) && c.maxStringLength >= 0),
    `${source}: "maxStringLength" must be a non-negative integer`,
  );
  for (const k of ["disable", "allow", "allowPatterns"] as const)
    expect(c[k] === undefined || isStrArray(c[k]), `${source}: "${k}" must be an array of strings`);
  expect(
    c.categories === undefined ||
      (isStrArray(c.categories) && c.categories.every((x) => x === "secret" || x === "pii")),
    `${source}: "categories" may only contain "secret" and "pii"`,
  );
  expect(c.auditLog === undefined || (typeof c.auditLog === "string" && c.auditLog.length > 0),
    `${source}: "auditLog" must be a file path`);

  for (const [i, p] of (c.allowPatterns ?? []).entries()) {
    try {
      new RegExp(p);
    } catch (e) {
      throw new ConfigError(`${source}: allowPatterns[${i}] is not a valid regex: ${(e as Error).message}`);
    }
  }

  expect(c.rules === undefined || Array.isArray(c.rules), `${source}: "rules" must be an array`);
  const ids = new Set(DEFAULT_RULES.map((r) => r.id));
  for (const [i, r] of (c.rules ?? []).entries()) {
    const where = `${source}: rules[${i}]`;
    expect(isObj(r), `${where} must be an object`);
    checkKeys(r, RULE_KEYS, where);
    expect(typeof r.id === "string" && /^[a-z0-9][a-z0-9-]*$/.test(r.id),
      `${where}: "id" must be lowercase letters, digits and dashes`);
    expect(!ids.has(r.id) && r.id !== SENSITIVE_KEY_RULE.id, `${where}: id "${r.id}" is already in use`);
    ids.add(r.id);
    expect(typeof r.pattern === "string" && r.pattern.length > 0, `${where} (${r.id}): "pattern" is required`);
    expect(r.label === undefined || (typeof r.label === "string" && /^[A-Z0-9_]+$/.test(r.label)),
      `${where} (${r.id}): "label" must be UPPER_SNAKE_CASE`);
    expect(r.category === undefined || r.category === "secret" || r.category === "pii",
      `${where} (${r.id}): "category" must be "secret" or "pii"`);
    expect(r.flags === undefined || (typeof r.flags === "string" && /^[imsu]*$/.test(r.flags)),
      `${where} (${r.id}): "flags" may only contain i, m, s, u`);
    expect(r.group === undefined || (Number.isInteger(r.group) && r.group >= 1),
      `${where} (${r.id}): "group" must be a positive integer`);
    expect(r.minEntropy === undefined || (typeof r.minEntropy === "number" && r.minEntropy >= 0),
      `${where} (${r.id}): "minEntropy" must be a non-negative number`);
    let re: RegExp;
    try {
      re = new RegExp(r.pattern, r.flags ?? "");
    } catch (e) {
      throw new ConfigError(`${where} (${r.id}): invalid regex: ${(e as Error).message}`);
    }
    expect(!re.test(""), `${where} (${r.id}): pattern matches the empty string`);
    if (r.group !== undefined) {
      const groups = new RegExp(`${r.pattern}|`, r.flags ?? "").exec("")!.length - 1;
      expect(r.group <= groups, `${where} (${r.id}): pattern has only ${groups} capture group(s)`);
    }
  }

  const checkDisable = (list: string[] | undefined, where: string) => {
    for (const id of list ?? []) {
      if (!ids.has(id) && id !== SENSITIVE_KEY_RULE.id) {
        const hint = closest(id, [...ids, SENSITIVE_KEY_RULE.id]);
        throw new ConfigError(`${where}: unknown rule id "${id}"${hint ? ` (did you mean "${hint}"?)` : ""}`);
      }
    }
  };
  checkDisable(c.disable, `${source}: disable`);

  expect(c.tools === undefined || isObj(c.tools), `${source}: "tools" must be an object keyed by tool name`);
  for (const [name, p] of Object.entries(c.tools ?? {})) {
    const where = `${source}: tools["${name}"]`;
    expect(isObj(p), `${where} must be an object`);
    checkKeys(p, TOOL_KEYS, where);
    expect(p.skip === undefined || typeof p.skip === "boolean", `${where}: "skip" must be true or false`);
    expect(p.disable === undefined || isStrArray(p.disable), `${where}: "disable" must be an array of strings`);
    checkDisable(p.disable, `${where}.disable`);
  }
  return c;
}

/** Read, parse and validate a config file. Relative paths inside resolve from its folder. */
export function loadConfig(file: string): GuardrailConfig {
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new ConfigError(`cannot read config "${file}": ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigError(`config "${file}" is not valid JSON: ${(e as Error).message}`);
  }
  const cfg = validateConfig(raw, path.basename(file));
  if (cfg.auditLog) cfg.auditLog = path.resolve(path.dirname(file), cfg.auditLog);
  return cfg;
}

/** Turn validated custom rules into DetectionRules. */
export function compileRules(rules: CustomRuleConfig[] = []): DetectionRule[] {
  return rules.map((r) => {
    const flags = new Set([...(r.flags ?? ""), "g"]);
    if (r.group !== undefined) flags.add("d");
    const minEntropy = r.minEntropy;
    return {
      id: r.id,
      label: r.label ?? r.id.toUpperCase().replace(/-/g, "_"),
      category: r.category ?? "secret",
      pattern: new RegExp(r.pattern, [...flags].join("")),
      group: r.group,
      validate: minEntropy !== undefined ? (v: string) => shannonEntropy(v) >= minEntropy : undefined,
    };
  });
}

/**
 * Probe custom rules with adversarial inputs and return the ids of slow
 * ones. User-written regexes can backtrack catastrophically, and a slow rule
 * would stall every MCP response. A regex can't be interrupted on the main
 * thread, so the probe runs in a worker that is terminated on timeout.
 */
export async function findSlowRules(
  rules: CustomRuleConfig[],
  budgetMs = 150,
  timeoutMs = 3000,
): Promise<{ id: string; reason: string }[]> {
  if (rules.length === 0) return [];
  const { Worker } = await import("node:worker_threads");
  const slow: { id: string; reason: string }[] = [];
  for (const r of rules) {
    const code = `
      const { parentPort, workerData: { source, flags, budget } } = require("node:worker_threads");
      const units = ["a","a.","a-","a ","aa:","a=","1","1 ","a@","_","=","x/","A1","a!",".","-"," "];
      // Long run of one character, then one that fails the match: the shape
      // that triggers exponential backtracking in patterns like (a+)+$.
      const runs = ["a","A","1","_","-"," ","."].flatMap(c => ["!", "\\n", "@", "\\u0000"].map(t => [c, t]));
      const re = new RegExp(source, flags);
      let worst = 0, sample = "";
      for (const size of [30, 200, 2000, 20000]) {
        const inputs = [
          ...units.map(u => [u, u.repeat(Math.ceil(size / u.length)).slice(0, size)]),
          ...runs.map(([c, t]) => [c + "…" + t, c.repeat(size) + t]),
        ];
        for (const [u, input] of inputs) {
          const t0 = performance.now();
          re.lastIndex = 0;
          for (const _ of input.matchAll(re)) {}
          const ms = performance.now() - t0;
          if (ms > worst) { worst = ms; sample = u; }
        }
        if (worst > budget) break;
      }
      parentPort.postMessage({ worst, sample });
    `;
    const flags = [...new Set([...(r.flags ?? ""), "g"])].join("");
    const res = await new Promise<{ worst: number; sample: string } | "timeout" | Error>((resolve) => {
      const w = new Worker(code, { eval: true, workerData: { source: r.pattern, flags, budget: budgetMs } });
      const t = setTimeout(() => {
        void w.terminate();
        resolve("timeout");
      }, timeoutMs);
      w.once("message", (m) => {
        clearTimeout(t);
        void w.terminate();
        resolve(m);
      });
      w.once("error", (e) => {
        clearTimeout(t);
        resolve(e);
      });
    });
    if (res === "timeout")
      slow.push({ id: r.id, reason: `did not finish within ${timeoutMs} ms on adversarial input (runaway backtracking)` });
    else if (res instanceof Error) slow.push({ id: r.id, reason: res.message });
    else if (res.worst > budgetMs)
      slow.push({ id: r.id, reason: `took ${Math.round(res.worst)} ms on 20 KB of ${JSON.stringify(res.sample)}` });
  }
  return slow;
}
