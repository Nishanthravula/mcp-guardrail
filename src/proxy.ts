import { spawn, ChildProcess } from "node:child_process";
import { constants as osConstants } from "node:os";
import { Sanitizer, SanitizerOptions, RedactionDetail } from "./sanitizer.js";
import { AuditLog } from "./audit.js";
import type { InjectionMode, ToolPolicy } from "./config.js";
import { InjectionDetector } from "./injection/detector.js";
import { VERSION } from "./version.js";

export interface ProxyOptions extends SanitizerOptions {
  /** Command to launch the wrapped MCP server. */
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  /**
   * "responses" (default): redact server → client traffic (tool results,
   * resources, logs) — the data that ends up in the LLM context.
   * "both": additionally BLOCK client → server requests whose arguments
   * contain a detected secret, so the model can't send secrets to the
   * server. Requests are never rewritten: silently changing what gets
   * written would corrupt the user's data.
   */
  direction?: "responses" | "both";
  /**
   * Block client → server requests that contain a redaction placeholder,
   * e.g. a model writing back a file it only saw redacted, which would
   * replace real secrets on disk with "[REDACTED:...]". Default true.
   */
  blockPlaceholders?: boolean;
  /** Write redaction summaries to stderr. Default true. */
  logToStderr?: boolean;
  /** Grace period after the client closes stdin before the server is terminated (ms). Default 5000. */
  shutdownGraceMs?: number;
  /** Per-tool policies, keyed by MCP tool name. */
  tools?: Record<string, ToolPolicy>;
  /** Detect prompt injections in tool results. Off unless a mode is given here or per tool. */
  injection?: { mode: InjectionMode; threshold?: number };
  /**
   * Report what would be redacted or blocked, but forward everything
   * unchanged. For trying the guardrail out before trusting it.
   */
  dryRun?: boolean;
  /** Append a JSONL audit log (rules, tools, JSON paths, fingerprints — never values). */
  auditLog?: string;
}

/**
 * Newline-delimited JSON-RPC framing (the MCP stdio transport).
 *
 * Works on raw bytes: chunks are split on 0x0A and each complete line is
 * decoded once, so multi-byte UTF-8 characters that straddle a chunk
 * boundary are never corrupted. Only the newly arrived chunk is searched,
 * so a large message costs O(n), not O(n²).
 */
export class LineBuffer {
  private parts: Buffer[] = [];

  push(chunk: Buffer | string, onLine: (line: string) => void): void {
    const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    let start = 0;
    let idx: number;
    while ((idx = buf.indexOf(0x0a, start)) !== -1) {
      const piece = buf.subarray(start, idx);
      const whole = this.parts.length > 0 ? Buffer.concat([...this.parts, piece]) : piece;
      this.parts = [];
      this.emit(whole, onLine);
      start = idx + 1;
    }
    if (start < buf.length) this.parts.push(buf.subarray(start));
  }

  /** Emit whatever is left (a final message with no trailing newline). */
  flush(onLine: (line: string) => void): void {
    if (this.parts.length === 0) return;
    const whole = Buffer.concat(this.parts);
    this.parts = [];
    this.emit(whole, onLine);
  }

  private emit(bytes: Buffer, onLine: (line: string) => void): void {
    let line = bytes.toString("utf8");
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line.trim().length > 0) onLine(line);
  }
}

/** Envelope fields that must never be altered (the client matches on them). */
const ENVELOPE_KEYS = new Set(["jsonrpc", "id", "method"]);
/** Bound on in-flight tools/call requests we remember (guards against id leaks). */
const MAX_PENDING = 10_000;

type JsonObject = Record<string, unknown>;
const isObject = (v: unknown): v is JsonObject =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const idKey = (id: unknown) => `${typeof id}:${String(id)}`;

interface Block {
  reason: "placeholder" | "secret";
  labels?: string[];
  message: string;
}

export class GuardrailProxy {
  private child: ChildProcess | null = null;
  private sanitizer: Sanitizer;
  private toolSanitizers = new Map<string, Sanitizer>();
  private requestScanner: Sanitizer | null;
  private opts: ProxyOptions;
  private placeholderPrefix: string;
  private pendingTools = new Map<string, string>();
  private audit: AuditLog | null;
  private detector: InjectionDetector | null = null;

  constructor(options: ProxyOptions) {
    this.opts = {
      direction: "responses",
      logToStderr: true,
      blockPlaceholders: true,
      shutdownGraceMs: 5000,
      ...options,
    };
    this.audit = options.auditLog ? new AuditLog(options.auditLog) : null;
    const base: SanitizerOptions = {
      ...options,
      fingerprint: this.audit?.fingerprint ?? options.fingerprint,
    };
    this.sanitizer = new Sanitizer(base);
    // Load the model only when some tool can use it, and fail at startup, not
    // mid-session, if it is missing or corrupted.
    const modes = [options.injection?.mode, ...Object.values(options.tools ?? {}).map((p) => p.injection)];
    if (modes.some((m) => m === "report" || m === "block")) {
      this.detector = new InjectionDetector({ threshold: options.injection?.threshold });
    }
    for (const [name, policy] of Object.entries(options.tools ?? {})) {
      if (!policy.skip && policy.disable?.length) {
        this.toolSanitizers.set(
          name,
          new Sanitizer({ ...base, disable: [...(base.disable ?? []), ...policy.disable] }),
        );
      }
    }
    // Requests are only checked for secrets (not PII): paths and arguments
    // legitimately contain names and emails the user typed.
    this.requestScanner =
      this.opts.direction === "both"
        ? new Sanitizer({ ...options, categories: ["secret"], maxStringLength: 0 })
        : null;
    const probe = (options.placeholder ?? ((l: string) => `[REDACTED:${l}]`))("\u0000");
    this.placeholderPrefix = probe.slice(0, probe.indexOf("\u0000"));
  }

  start(): void {
    const { command, args = [], env } = this.opts;
    if (this.opts.dryRun) {
      this.log("DRY RUN: nothing is redacted or blocked; findings are only reported");
    }
    this.audit?.write({
      event: "start",
      version: VERSION,
      dryRun: !!this.opts.dryRun,
      // Server args can carry tokens (e.g. --api-key ...), so scrub them too.
      server: this.sanitizer.sanitizeString([command, ...args].join(" ")).output,
      pid: process.pid,
    });

    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "inherit"],
    });
    this.child = child;

    child.on("error", (err: NodeJS.ErrnoException) => {
      process.stderr.write(`mcp-guardrail: could not start "${command}": ${err.message}\n`);
      this.audit?.close();
      process.exit(err.code === "ENOENT" ? 127 : 1);
    });
    // The server may exit while we are still writing to it.
    child.stdin?.on("error", () => {});

    const toServer = new LineBuffer();
    const toClient = new LineBuffer();

    // client (LLM host) → server
    process.stdin.on("data", (chunk: Buffer) => {
      toServer.push(chunk, (line) => this.handleClientLine(line));
    });
    process.stdin.on("end", () => {
      toServer.flush((line) => this.handleClientLine(line));
      // Pass EOF on, as the MCP stdio shutdown sequence expects; escalate if
      // the server ignores it.
      child.stdin?.end();
      const grace = this.opts.shutdownGraceMs ?? 5000;
      setTimeout(() => child.kill("SIGTERM"), grace).unref();
      setTimeout(() => child.kill("SIGKILL"), grace * 2).unref();
    });

    // server → client (this is what lands in the LLM context)
    child.stdout?.on("data", (chunk: Buffer) => {
      toClient.push(chunk, (line) => this.writeToClient(this.processServerLine(line)));
    });

    // 'close' fires only after the server's stdout is fully drained, so the
    // final response is never cut off.
    child.on("close", (code, signal) => {
      toClient.flush((line) => this.writeToClient(this.processServerLine(line)));
      const exitCode =
        code ?? (signal ? 128 + (osConstants.signals[signal as NodeJS.Signals] ?? 0) : 0);
      this.audit?.write({ event: "stop", exitCode });
      this.audit?.close();
      process.stdout.write("", () => process.exit(exitCode));
    });

    for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"] as const) {
      process.on(sig, () => child.kill(sig));
    }
  }

  private writeToClient(line: string): void {
    process.stdout.write(line + "\n");
  }

  private log(msg: string): void {
    if (this.opts.logToStderr) process.stderr.write(`[mcp-guardrail] ${msg}\n`);
  }

  // ---------------------------------------------------------------- client → server

  private handleClientLine(line: string): void {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      this.child?.stdin?.write(line + "\n");
      return;
    }
    const msgs = Array.isArray(msg) ? msg : [msg];
    for (const m of msgs) this.trackToolCall(m);

    const blocked = msgs.map((m) => (isObject(m) ? this.checkRequest(m) : null));
    for (const [i, b] of blocked.entries()) if (b) this.reportBlock(msgs[i] as JsonObject, b);

    if (this.opts.dryRun || blocked.every((b) => b === null)) {
      // Forward the original bytes untouched.
      this.child?.stdin?.write(line + "\n");
      return;
    }
    const forward = msgs.filter((_, i) => blocked[i] === null);
    const replies = msgs
      .map((m, i) => (blocked[i] ? this.blockReply(m as JsonObject, blocked[i]!.message) : null))
      .filter((r): r is JsonObject => r !== null);
    for (const [i, b] of blocked.entries()) if (b) this.untrack((msgs[i] as JsonObject).id);
    if (forward.length > 0) {
      const out = Array.isArray(msg) ? forward : forward[0];
      this.child?.stdin?.write(JSON.stringify(out) + "\n");
    }
    for (const r of replies) this.writeToClient(JSON.stringify(r));
  }

  /** Remember which tool each tools/call id is for, to apply per-tool policies. */
  private trackToolCall(m: unknown): void {
    if (!isObject(m) || m.method !== "tools/call" || m.id === undefined || !isObject(m.params)) return;
    const name = m.params.name;
    if (typeof name !== "string") return;
    if (this.pendingTools.size >= MAX_PENDING) {
      const oldest = this.pendingTools.keys().next().value;
      if (oldest !== undefined) this.pendingTools.delete(oldest);
    }
    this.pendingTools.set(idKey(m.id), name);
  }

  private untrack(id: unknown): string | undefined {
    if (id === undefined) return undefined;
    const k = idKey(id);
    const tool = this.pendingTools.get(k);
    this.pendingTools.delete(k);
    return tool;
  }

  /** Returns why the request must not reach the server, or null. */
  private checkRequest(m: JsonObject): Block | null {
    const payload = { params: m.params, result: m.result };
    if (this.opts.blockPlaceholders && this.placeholderPrefix) {
      if (JSON.stringify(payload).includes(this.placeholderPrefix)) {
        return {
          reason: "placeholder",
          message:
            `mcp-guardrail blocked this request: its arguments contain a redaction placeholder ` +
            `(${this.placeholderPrefix}...). Sending it would overwrite the real, hidden value with the ` +
            `placeholder. Make a targeted edit that leaves the redacted text untouched, or ask the user ` +
            `to make this change themselves.`,
        };
      }
    }
    if (this.requestScanner) {
      const { redactions } = this.requestScanner.sanitize(payload);
      if (redactions.length > 0) {
        const labels = redactions.map((r) => r.label);
        return {
          reason: "secret",
          labels,
          message:
            `mcp-guardrail blocked this request: its arguments contain a secret (${labels.join(", ")}). ` +
            `Secrets are not sent to this server (--both). Ask the user to make this change themselves.`,
        };
      }
    }
    return null;
  }

  private reportBlock(m: JsonObject, b: Block): void {
    const method = typeof m.method === "string" ? m.method : undefined;
    const tool = isObject(m.params) && typeof m.params.name === "string" ? m.params.name : undefined;
    const what = `${method ?? "response"}${tool ? ` (${tool})` : ""}`;
    this.log(`request: ${this.opts.dryRun ? "would block" : "blocked"} ${what}: ${b.reason}`);
    this.audit?.write({
      event: this.opts.dryRun ? "would-block" : "block",
      method,
      tool,
      id: m.id as string | number | undefined,
      reason: b.reason,
      labels: b.labels,
    });
  }

  private blockReply(m: JsonObject, reason: string): JsonObject | null {
    if (m.id === undefined || typeof m.method !== "string") return null; // notification / response: drop
    if (m.method === "tools/call") {
      // A tool-level error lets the model read the reason and adjust.
      return {
        jsonrpc: "2.0",
        id: m.id,
        result: { content: [{ type: "text", text: reason }], isError: true },
      };
    }
    return { jsonrpc: "2.0", id: m.id, error: { code: -32602, message: reason } };
  }

  // ---------------------------------------------------------------- server → client

  private processServerLine(line: string): string {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      // Not JSON (e.g. a server logging to stdout by mistake) — still scrub it.
      const { output, hits } = this.sanitizer.sanitizeString(line);
      if (hits.size > 0) {
        const rs = [...hits.values()];
        this.log(`response (non-JSON line): ${this.opts.dryRun ? "would redact" : "redacted"} ${summary(rs)}`);
        this.audit?.write({
          event: this.opts.dryRun ? "would-redact" : "redact",
          method: "(non-JSON stdout)",
          redactions: Object.fromEntries(rs.map((r) => [r.label, r.count])),
          details: [],
        });
      }
      return this.opts.dryRun ? line : output;
    }
    const msgs = Array.isArray(msg) ? msg : [msg];
    let changed = false;
    const out = msgs.map((m) => {
      if (!isObject(m)) {
        const r = this.sanitizer.sanitize(m);
        if (r.redactions.length) changed = true;
        return r.value;
      }
      const s = this.sanitizeEnvelope(m);
      if (s !== m) changed = true;
      return s;
    });
    if (this.opts.dryRun || !changed) return line;
    return JSON.stringify(Array.isArray(msg) ? out : out[0]);
  }

  /** Sanitize everything except jsonrpc / id / method. Returns `m` itself if nothing changed. */
  private sanitizeEnvelope(m: JsonObject): JsonObject {
    const tool = typeof m.method === "string" ? undefined : this.untrack(m.id);
    const policy = tool ? this.opts.tools?.[tool] : undefined;
    if (policy?.skip) return m;
    const sanitizer = (tool && this.toolSanitizers.get(tool)) || this.sanitizer;

    const body: JsonObject = {};
    for (const [k, v] of Object.entries(m)) if (!ENVELOPE_KEYS.has(k)) body[k] = v;
    const { value, redactions, details, truncated } = sanitizer.sanitize(body);
    const redacted = redactions.length > 0 || truncated > 0;
    // Injection screening runs on the redacted text, so it never sees a secret.
    let clean: JsonObject = redacted ? value : body;
    const mode = tool ? (policy?.injection ?? this.opts.injection?.mode ?? "off") : "off";
    if (tool && mode !== "off" && this.detector && isObject(clean.result)) {
      const screened = this.screenResult(clean.result, tool, m.id, mode);
      if (screened !== clean.result) clean = { ...clean, result: screened };
    }
    if (!redacted && clean === body) return m;

    const method = typeof m.method === "string" ? m.method : undefined;
    const where = method ?? (tool ? `tools/call (${tool})` : "response");
    if (redacted) this.log(
      `${where}: ${this.opts.dryRun ? "would redact" : "redacted"} ${summary(redactions)}` +
        (truncated ? `, truncated ${truncated} value(s)` : ""),
    );
    if (redactions.length > 0) {
      this.audit?.write({
        event: this.opts.dryRun ? "would-redact" : "redact",
        method,
        tool,
        id: m.id as string | number | undefined,
        redactions: Object.fromEntries(redactions.map((r) => [r.label, r.count])),
        details: details.map((d: RedactionDetail) => ({ rule: d.ruleId, path: d.path, fp: d.fingerprint })),
      });
    }
    const out: JsonObject = {};
    for (const k of Object.keys(m)) out[k] = ENVELOPE_KEYS.has(k) ? m[k] : clean[k];
    return out;
  }

  /**
   * Score every text item of a tool result. Logs each suspected injection
   * (location and score only, never the text) and, in block mode, returns a
   * copy with the flagged items replaced by a notice. Returns `result` itself
   * when nothing is withheld.
   */
  private screenResult(result: JsonObject, tool: string, id: unknown, mode: "report" | "block"): JsonObject {
    const detector = this.detector!;
    const flagged: { keys: (string | number)[]; score: number }[] = [];
    const visit = (text: unknown, keys: (string | number)[]) => {
      if (typeof text !== "string" || text === "") return;
      const r = detector.score(text);
      if (!r.flagged) return;
      flagged.push({ keys, score: r.score });
      const path = "result" + keys.map((k) => (typeof k === "number" ? `[${k}]` : `.${k}`)).join("");
      const shown = r.score.toFixed(2);
      const withhold = mode === "block";
      this.log(
        `tools/call (${tool}): injection suspected at ${path} (score ${shown})` +
          (withhold ? (this.opts.dryRun ? " — would withhold" : " — withheld") : ""),
      );
      this.audit?.write({
        event: this.opts.dryRun ? "would-injection" : "injection",
        tool,
        id: id as string | number | undefined,
        path,
        score: Math.round(r.score * 1000) / 1000,
        threshold: detector.threshold,
        model: detector.modelName,
        action: mode,
        truncated: r.truncated,
      });
    };
    const walk = (v: unknown, keys: (string | number)[]) => {
      if (typeof v === "string") visit(v, keys);
      else if (Array.isArray(v)) v.forEach((x, i) => walk(x, [...keys, i]));
      else if (isObject(v)) for (const [k, x] of Object.entries(v)) walk(x, [...keys, k]);
    };
    if (Array.isArray(result.content)) {
      result.content.forEach((item, i) => {
        if (!isObject(item)) return;
        if (item.type === "text") visit(item.text, ["content", i, "text"]);
        // Embedded resources (e.g. a file returned alongside a summary) carry text too.
        else if (item.type === "resource" && isObject(item.resource)) {
          visit(item.resource.text, ["content", i, "resource", "text"]);
        }
      });
    }
    walk(result.structuredContent, ["structuredContent"]);

    if (mode !== "block" || this.opts.dryRun || flagged.length === 0) return result;
    const copy = structuredClone(result);
    for (const { keys, score } of flagged) {
      let node: any = copy;
      for (const k of keys.slice(0, -1)) node = node[k];
      node[keys[keys.length - 1]] =
        `[mcp-guardrail: withheld — this tool result looks like a prompt injection (score ${score.toFixed(2)}). ` +
        "Run with --dry-run to inspect.]";
    }
    return copy;
  }
}

function summary(rs: { label: string; count: number }[]): string {
  return rs.map((r) => `${r.label}×${r.count}`).join(", ") || "nothing";
}
