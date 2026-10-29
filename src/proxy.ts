import { spawn, ChildProcess } from "node:child_process";
import { constants as osConstants } from "node:os";
import { Sanitizer, SanitizerOptions } from "./sanitizer.js";

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

type JsonObject = Record<string, unknown>;
const isObject = (v: unknown): v is JsonObject =>
  v !== null && typeof v === "object" && !Array.isArray(v);

export class GuardrailProxy {
  private child: ChildProcess | null = null;
  private sanitizer: Sanitizer;
  private requestScanner: Sanitizer | null;
  private opts: ProxyOptions;
  private placeholderPrefix: string;

  constructor(options: ProxyOptions) {
    this.opts = {
      direction: "responses",
      logToStderr: true,
      blockPlaceholders: true,
      shutdownGraceMs: 5000,
      ...options,
    };
    this.sanitizer = new Sanitizer(options);
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
    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "inherit"],
    });
    this.child = child;

    child.on("error", (err: NodeJS.ErrnoException) => {
      process.stderr.write(`mcp-guardrail: could not start "${command}": ${err.message}\n`);
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
    const blocked = msgs.map((m) => (isObject(m) ? this.checkRequest(m) : null));
    if (blocked.every((b) => b === null)) {
      // Forward the original bytes untouched.
      this.child?.stdin?.write(line + "\n");
      return;
    }
    const forward = msgs.filter((_, i) => blocked[i] === null);
    const replies = msgs
      .map((m, i) => (blocked[i] ? this.blockReply(m as JsonObject, blocked[i]!) : null))
      .filter((r): r is JsonObject => r !== null);
    if (forward.length > 0) {
      const out = Array.isArray(msg) ? forward : forward[0];
      this.child?.stdin?.write(JSON.stringify(out) + "\n");
    }
    for (const r of replies) this.writeToClient(JSON.stringify(r));
  }

  /** Returns a reason string if the request must not reach the server. */
  private checkRequest(m: JsonObject): string | null {
    const payload = { params: m.params, result: m.result };
    if (this.opts.blockPlaceholders && this.placeholderPrefix) {
      if (JSON.stringify(payload).includes(this.placeholderPrefix)) {
        return (
          `mcp-guardrail blocked this request: its arguments contain a redaction placeholder ` +
          `(${this.placeholderPrefix}...). Sending it would overwrite the real, hidden value with the ` +
          `placeholder. Make a targeted edit that leaves the redacted text untouched, or ask the user ` +
          `to make this change themselves.`
        );
      }
    }
    if (this.requestScanner) {
      const { redactions } = this.requestScanner.sanitize(payload);
      if (redactions.length > 0) {
        const labels = redactions.map((r) => r.label).join(", ");
        return (
          `mcp-guardrail blocked this request: its arguments contain a secret (${labels}). ` +
          `Secrets are not sent to this server (--both). Ask the user to make this change themselves.`
        );
      }
    }
    return null;
  }

  private blockReply(m: JsonObject, reason: string): JsonObject | null {
    const name = typeof m.method === "string" ? m.method : "response";
    this.log(`request: blocked ${name}`);
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
      if (hits.size > 0) this.log(`response (non-JSON line): redacted ${summary([...hits.values()])}`);
      return output;
    }
    const msgs = Array.isArray(msg) ? msg : [msg];
    const out = msgs.map((m) => (isObject(m) ? this.sanitizeEnvelope(m) : this.sanitizer.sanitize(m).value));
    return JSON.stringify(Array.isArray(msg) ? out : out[0]);
  }

  /** Sanitize everything except jsonrpc / id / method. */
  private sanitizeEnvelope(m: JsonObject): JsonObject {
    const body: JsonObject = {};
    for (const [k, v] of Object.entries(m)) if (!ENVELOPE_KEYS.has(k)) body[k] = v;
    const { value, redactions, truncated } = this.sanitizer.sanitize(body);
    if (redactions.length > 0 || truncated > 0) {
      this.log(
        `response: redacted ${summary(redactions)}${truncated ? `, truncated ${truncated} value(s)` : ""}`,
      );
    }
    const out: JsonObject = {};
    for (const k of Object.keys(m)) out[k] = ENVELOPE_KEYS.has(k) ? m[k] : value[k];
    return out;
  }
}

function summary(rs: { label: string; count: number }[]): string {
  return rs.map((r) => `${r.label}×${r.count}`).join(", ") || "nothing";
}
