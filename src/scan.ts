/**
 * `mcp-guardrail scan`: report what the guardrail would redact in files,
 * folders or stdin. Prints locations and rule labels, never the values.
 */
import fs from "node:fs";
import path from "node:path";
import { Sanitizer } from "./sanitizer.js";

export interface ScanFinding {
  file: string;
  line: number;
  column: number;
  ruleId: string;
  label: string;
  category: "secret" | "pii";
  /** The line with every finding on it replaced by its placeholder. */
  context: string;
}

export interface ScanReport {
  findings: ScanFinding[];
  filesScanned: number;
  skipped: { file: string; reason: string }[];
}

const SKIP_DIRS = new Set([".git", "node_modules", ".hg", ".svn"]);
const MAX_BYTES = 10 * 1024 * 1024;
const CONTEXT_WIDTH = 160;

/** Scan a string as if it were a file called `name`. */
export function scanText(sanitizer: Sanitizer, text: string, name: string): ScanFinding[] {
  const found = sanitizer.findings(text);
  if (found.length === 0) return [];

  const lineStarts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) lineStarts.push(i + 1);
  const lineOf = (offset: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineStarts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  };

  // Redact every finding on a line before showing it, so context can never
  // reveal a neighbouring secret.
  const contextCache = new Map<number, string>();
  const contextFor = (li: number, focus: number): string => {
    const start = lineStarts[li];
    const end = li + 1 < lineStarts.length ? lineStarts[li + 1] - 1 : text.length;
    let s = contextCache.get(li);
    if (s === undefined) {
      s = "";
      let cur = start;
      for (const f of found) {
        if (f.end <= start || f.start >= end) continue;
        s += text.slice(cur, Math.max(cur, f.start)) + `[${f.label}]`;
        cur = Math.max(cur, f.end);
      }
      s += text.slice(cur, Math.max(cur, end));
      s = s.replace(/\r$/, "").replace(/\t/g, " ");
      contextCache.set(li, s);
    }
    if (s.length <= CONTEXT_WIDTH) return s.trim();
    // Long (e.g. minified) lines: show a window around the finding's placeholder.
    const at = Math.max(0, Math.min(s.length, focus - start));
    const from = Math.max(0, at - CONTEXT_WIDTH / 2);
    return (from > 0 ? "…" : "") + s.slice(from, from + CONTEXT_WIDTH).trim() + (from + CONTEXT_WIDTH < s.length ? "…" : "");
  };

  return found.map((f) => {
    const li = lineOf(f.start);
    // Column in characters (1-based) on the original line.
    return {
      file: name,
      line: li + 1,
      column: f.start - lineStarts[li] + 1,
      ruleId: f.ruleId,
      label: f.label,
      category: f.category,
      context: contextFor(li, f.start),
    };
  });
}

function* walk(target: string, skipped: ScanReport["skipped"]): Generator<string> {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(target);
  } catch (e) {
    skipped.push({ file: target, reason: (e as NodeJS.ErrnoException).code ?? "unreadable" });
    return;
  }
  if (st.isSymbolicLink()) return; // never follow links out of the tree
  if (st.isFile()) {
    yield target;
    return;
  }
  if (!st.isDirectory()) return;
  for (const entry of fs.readdirSync(target).sort()) {
    if (SKIP_DIRS.has(entry)) continue;
    yield* walk(path.join(target, entry), skipped);
  }
}

/** Scan files and folders (recursively). "-" reads stdin. */
export function scanPaths(sanitizer: Sanitizer, targets: string[], stdin?: () => string): ScanReport {
  const report: ScanReport = { findings: [], filesScanned: 0, skipped: [] };
  for (const t of targets) {
    if (t === "-") {
      report.filesScanned++;
      report.findings.push(...scanText(sanitizer, stdin ? stdin() : fs.readFileSync(0, "utf8"), "<stdin>"));
      continue;
    }
    for (const file of walk(t, report.skipped)) {
      const size = fs.statSync(file).size;
      if (size > MAX_BYTES) {
        report.skipped.push({ file, reason: `larger than ${MAX_BYTES / 1024 / 1024} MB` });
        continue;
      }
      const buf = fs.readFileSync(file);
      if (buf.subarray(0, 8000).includes(0)) {
        report.skipped.push({ file, reason: "binary" });
        continue;
      }
      report.filesScanned++;
      report.findings.push(...scanText(sanitizer, buf.toString("utf8"), file));
    }
  }
  return report;
}

export function formatReport(report: ScanReport, color: boolean): string {
  const c = (code: string, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const lines: string[] = [];
  for (const f of report.findings) {
    lines.push(
      `${c("1", `${f.file}:${f.line}:${f.column}`)}  ${c(f.category === "secret" ? "31" : "33", f.label)}  ${c("2", f.ruleId)}`,
      `    ${f.context}`,
    );
  }
  const files = new Set(report.findings.map((f) => f.file)).size;
  const n = report.findings.length;
  lines.push(
    "",
    n === 0
      ? c("32", `No findings in ${report.filesScanned} file(s).`)
      : `${n} finding(s) in ${files} file(s); ${report.filesScanned} file(s) scanned.`,
  );
  if (report.skipped.length) lines.push(c("2", `Skipped ${report.skipped.length} file(s) (binary, too large or unreadable).`));
  return lines.join("\n");
}
