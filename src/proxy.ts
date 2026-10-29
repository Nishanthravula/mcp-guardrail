import { spawn, ChildProcess } from "node:child_process";
import { Sanitizer, SanitizerOptions } from "./sanitizer.js";

export interface ProxyOptions extends SanitizerOptions {
  /** Command to launch the wrapped MCP server. */
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  /**
   * Which directions to sanitize.
   * "responses" (default): sanitize server → client traffic (tool results,
   * resources) — the data that ends up in the LLM context.
   * "both": also sanitize client → server requests.
   */
  direction?: "responses" | "both";
  /** Write redaction summaries to stderr. Default true. */
  logToStderr?: boolean;
}

/**
 * Line-delimited JSON-RPC framing (the MCP stdio transport). Buffers partial
 * lines and yields complete messages.
 */
class LineBuffer {
  private buf = "";
  push(chunk: Buffer | string, onLine: (line: string) => void): void {
    this.buf += chunk.toString("utf8");
    let idx: number;
    while ((idx = this.buf.indexOf("\n")) !== -1) {
      const line = this.buf.slice(0, idx).replace(/\r$/, "");
      this.buf = this.buf.slice(idx + 1);
      if (line.trim().length > 0) onLine(line);
    }
  }
}

export class GuardrailProxy {
  private child: ChildProcess | null = null;
  private sanitizer: Sanitizer;
  private opts: ProxyOptions;

  constructor(options: ProxyOptions) {
    this.opts = { direction: "responses", logToStderr: true, ...options };
    this.sanitizer = new Sanitizer(options);
  }

  start(): void {
    const { command, args = [], env } = this.opts;
    this.child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "inherit"],
    });

    const toServer = new LineBuffer();
    const toClient = new LineBuffer();

    // client (LLM host) → server
    process.stdin.on("data", (chunk) => {
      toServer.push(chunk, (line) => {
        const out =
          this.opts.direction === "both" ? this.processLine(line, "request") : line;
        this.child?.stdin?.write(out + "\n");
      });
    });

    // server → client (this is what lands in the LLM context)
    this.child.stdout?.on("data", (chunk) => {
      toClient.push(chunk, (line) => {
        const out = this.processLine(line, "response");
        process.stdout.write(out + "\n");
      });
    });

    this.child.on("exit", (code) => process.exit(code ?? 0));
    process.on("SIGINT", () => this.child?.kill("SIGINT"));
    process.on("SIGTERM", () => this.child?.kill("SIGTERM"));
  }

  private processLine(line: string, dir: "request" | "response"): string {
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      // Not JSON — pass through untouched rather than corrupting the stream.
      return line;
    }

    const { value, redactions, truncated } = this.sanitizer.sanitize(msg);

    if (this.opts.logToStderr && (redactions.length > 0 || truncated > 0)) {
      const summary = redactions
        .map((r) => `${r.label}×${r.count}`)
        .join(", ");
      process.stderr.write(
        `[mcp-guardrail] ${dir}: redacted ${summary}${
          truncated ? `, truncated ${truncated} value(s)` : ""
        }\n`,
      );
    }

    return JSON.stringify(value);
  }
}
