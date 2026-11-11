#!/usr/bin/env node
/**
 * mcp-guardrail — sanitizing proxy for MCP servers.
 *
 *   mcp-guardrail [options] -- <server command...>   wrap a stdio MCP server
 *   mcp-guardrail scan [options] <path...|->         show what would be redacted
 *   mcp-guardrail check-config <file>                validate a config file
 */
import { GuardrailProxy, ProxyOptions } from "./proxy.js";
import { Sanitizer, SanitizerOptions } from "./sanitizer.js";
import { DEFAULT_RULES } from "./patterns.js";
import {
  ConfigError,
  GuardrailConfig,
  InjectionMode,
  compileRules,
  isThreshold,
  findSlowRules,
  loadConfig,
  validateConfig,
} from "./config.js";
import { scanPaths, formatReport } from "./scan.js";
import { InjectionDetector } from "./injection/detector.js";
import { VERSION } from "./version.js";

const HELP = `mcp-guardrail ${VERSION} — redact secrets and PII from MCP traffic

Usage:
  mcp-guardrail [options] -- <server command...>   wrap a stdio MCP server
  mcp-guardrail scan [options] <path...|->         show what would be redacted
  mcp-guardrail check-config <file>                validate a config file

Proxy options:
  --config <file>        JSON config (also: MCP_GUARDRAIL_CONFIG)
  --both                 also block requests that would send a secret to the server
  --allow-placeholders   let requests containing "[REDACTED:...]" through (not recommended)
  --max-string <n>       truncate string values longer than n characters (after redaction)
  --disable <ids>        comma-separated rule ids to turn off (e.g. email,phone)
  --detect-injection[=report|block]
                         flag tool results that look like prompt injections; "block"
                         also withholds the flagged text (default: report)
  --injection-threshold <p>
                         flag at or above this score, 0–1 (default: the model's own)
  --dry-run              report what would be redacted or blocked; change nothing
  --audit-log <file>     append a JSONL audit log (never contains values)
  --quiet                no stderr logs

Scan options:
  --config <file>, --disable <ids>
  --injection            also report files that look like prompt injections
  --injection-threshold <p>
  --json                 machine-readable output
  --no-color             plain output
  Exits 1 when anything is found, 0 when clean, 2 on error.

Rule ids: ${[...DEFAULT_RULES.map((r) => r.id), "sensitive-key"].join(", ")}
Docs: https://github.com/Nishanthravula/mcp-guardrail#readme
`;

function fail(msg: string): never {
  process.stderr.write(`mcp-guardrail: ${msg}\n`);
  process.exit(2);
}

interface Flags {
  config?: string;
  both?: boolean;
  allowPlaceholders?: boolean;
  maxString?: number;
  disable: string[];
  dryRun?: boolean;
  auditLog?: string;
  quiet?: boolean;
  injectionMode?: InjectionMode;
  injectionThreshold?: number;
  json?: boolean;
  color?: boolean;
  positional: string[];
}

function parseFlags(args: string[], mode: "proxy" | "scan"): Flags {
  const f: Flags = { disable: [], positional: [] };
  const value = (i: number, name: string) => {
    const v = args[i];
    if (v === undefined || v.startsWith("--")) fail(`${name} needs a value`);
    return v;
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const proxyOnly = () => mode === "proxy" || fail(`${a} is not a scan option`);
    const scanOnly = () => mode === "scan" || fail(`${a} only applies to scan`);
    if (a.startsWith("--detect-injection=")) {
      proxyOnly();
      const m = a.slice("--detect-injection=".length);
      if (m !== "report" && m !== "block") fail(`--detect-injection must be "report" or "block", got "${m}"`);
      f.injectionMode = m;
      continue;
    }
    switch (a) {
      case "--config": f.config = value(++i, a); break;
      case "--disable": f.disable.push(...value(++i, a).split(",").filter(Boolean)); break;
      case "--both": proxyOnly(); f.both = true; break;
      case "--allow-placeholders": proxyOnly(); f.allowPlaceholders = true; break;
      case "--max-string": {
        proxyOnly();
        const n = Number(value(++i, a));
        if (!Number.isInteger(n) || n < 0) fail("--max-string requires a non-negative integer");
        f.maxString = n;
        break;
      }
      case "--detect-injection": proxyOnly(); f.injectionMode = "report"; break;
      case "--injection": scanOnly(); f.injectionMode = "report"; break;
      case "--injection-threshold": {
        const p = Number(value(++i, a));
        if (!isThreshold(p)) fail("--injection-threshold requires a number between 0 and 1 (exclusive)");
        f.injectionThreshold = p;
        break;
      }
      case "--dry-run": proxyOnly(); f.dryRun = true; break;
      case "--audit-log": proxyOnly(); f.auditLog = value(++i, a); break;
      case "--quiet": f.quiet = true; break;
      case "--json": scanOnly(); f.json = true; break;
      case "--no-color": scanOnly(); f.color = false; break;
      default:
        if (a.startsWith("--")) fail(`unknown option ${a} (see --help)`);
        if (mode === "proxy") fail(`unexpected argument "${a}"; put the server command after --`);
        f.positional.push(a);
    }
  }
  return f;
}

/** Load the config file (if any) and merge flags over it. */
async function resolveConfig(f: Flags): Promise<GuardrailConfig> {
  const file = f.config ?? process.env.MCP_GUARDRAIL_CONFIG;
  let cfg: GuardrailConfig = {};
  try {
    if (file) cfg = loadConfig(file);
    // Validate flag-supplied rule ids against built-ins + the config's custom rules.
    if (f.disable.length) validateConfig({ rules: cfg.rules, disable: f.disable }, "--disable");
  } catch (e) {
    if (e instanceof ConfigError) fail(e.message);
    throw e;
  }
  const slow = await findSlowRules(cfg.rules ?? []);
  if (slow.length) {
    fail(
      "custom rule(s) too slow to run on every message:\n" +
        slow.map((s) => `  - ${s.id}: ${s.reason}`).join("\n") +
        "\n  Bound repetition (e.g. [A-Za-z0-9]{20,64} instead of .+) and avoid nested quantifiers.",
    );
  }
  return {
    ...cfg,
    both: f.both ?? cfg.both,
    allowPlaceholders: f.allowPlaceholders ?? cfg.allowPlaceholders,
    maxStringLength: f.maxString ?? cfg.maxStringLength,
    disable: [...(cfg.disable ?? []), ...f.disable],
    dryRun: f.dryRun ?? cfg.dryRun,
    auditLog: f.auditLog ?? cfg.auditLog,
    quiet: f.quiet ?? cfg.quiet,
    injection:
      f.injectionMode !== undefined || f.injectionThreshold !== undefined || cfg.injection
        ? {
            mode: f.injectionMode ?? cfg.injection?.mode,
            threshold: f.injectionThreshold ?? cfg.injection?.threshold,
          }
        : undefined,
  };
}

function sanitizerOptions(cfg: GuardrailConfig): SanitizerOptions {
  return {
    disable: cfg.disable,
    categories: cfg.categories,
    allow: cfg.allow,
    allowPatterns: cfg.allowPatterns?.map((p) => new RegExp(p)),
    extraRules: compileRules(cfg.rules),
    maxStringLength: cfg.maxStringLength ?? 0,
  };
}

async function main(argv: string[]): Promise<void> {
  if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (argv[0] === "--version" || argv[0] === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  if (argv[0] === "check-config") {
    const file = argv[1] ?? fail("usage: mcp-guardrail check-config <file>");
    const cfg = await resolveConfig({ config: file, disable: [], positional: [] });
    const rules = new Sanitizer(sanitizerOptions(cfg)).ruleIds;
    process.stdout.write(
      `${file}: OK\n` +
        `  active rules: ${rules.length} (${(cfg.rules ?? []).length} custom)\n` +
        `  allowlist: ${(cfg.allow ?? []).length} value(s), ${(cfg.allowPatterns ?? []).length} pattern(s)\n` +
        `  tool policies: ${Object.keys(cfg.tools ?? {}).join(", ") || "none"}\n` +
        `  injection detection: ${cfg.injection?.mode ?? "off"}` +
        (cfg.injection?.threshold !== undefined ? ` (threshold ${cfg.injection.threshold})` : "") +
        "\n" +
        (cfg.dryRun ? "  dry run: ON (nothing will be redacted)\n" : "") +
        (cfg.auditLog ? `  audit log: ${cfg.auditLog}\n` : ""),
    );
    return;
  }

  if (argv[0] === "scan") {
    const f = parseFlags(argv.slice(1), "scan");
    if (f.positional.length === 0) fail("usage: mcp-guardrail scan [options] <path...|->");
    const cfg = await resolveConfig(f);
    const detector = f.injectionMode ? new InjectionDetector({ threshold: cfg.injection?.threshold }) : undefined;
    const report = scanPaths(new Sanitizer(sanitizerOptions(cfg)), f.positional, undefined, detector);
    if (f.json) process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    else process.stdout.write(formatReport(report, f.color ?? process.stdout.isTTY === true) + "\n");
    process.exitCode = report.findings.length > 0 ? 1 : 0;
    return;
  }

  const sep = argv.indexOf("--");
  if (sep === -1 || sep === argv.length - 1) {
    fail("usage: mcp-guardrail [options] -- <server command...>  (see --help)");
  }
  const f = parseFlags(argv.slice(0, sep), "proxy");
  const cmd = argv.slice(sep + 1);
  const cfg = await resolveConfig(f);
  const opts: ProxyOptions = {
    ...sanitizerOptions(cfg),
    command: cmd[0],
    args: cmd.slice(1),
    direction: cfg.both ? "both" : "responses",
    blockPlaceholders: !cfg.allowPlaceholders,
    logToStderr: !cfg.quiet,
    tools: cfg.tools,
    injection: cfg.injection?.mode ? { mode: cfg.injection.mode, threshold: cfg.injection.threshold } : undefined,
    dryRun: cfg.dryRun,
    auditLog: cfg.auditLog,
  };
  try {
    new GuardrailProxy(opts).start();
  } catch (e) {
    fail((e as Error).message);
  }
}

main(process.argv.slice(2)).catch((e) => fail((e as Error).stack ?? String(e)));
