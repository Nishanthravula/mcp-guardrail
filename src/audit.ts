/**
 * JSONL audit log. Records what was redacted or blocked, where, and by which
 * rule — never the values. Each redacted value gets a short fingerprint (an
 * HMAC with a random per-run key), so you can tell "the same key leaked 40
 * times" from "40 different keys leaked" within one session, while the log
 * itself can't be used to recover or brute-force a secret.
 */
import fs from "node:fs";
import path from "node:path";
import { createHmac, randomBytes } from "node:crypto";

export type AuditEvent =
  | { event: "start"; version: string; dryRun: boolean; server: string; pid: number }
  | {
      event: "redact" | "would-redact";
      method?: string;
      tool?: string;
      id?: string | number;
      redactions: Record<string, number>;
      details: { rule: string; path: string; fp?: string }[];
    }
  | {
      event: "block" | "would-block";
      method?: string;
      tool?: string;
      id?: string | number;
      reason: "placeholder" | "secret";
      labels?: string[];
    }
  | { event: "stop"; exitCode: number };

export class AuditLog {
  private fd: number;
  private key = randomBytes(32);

  constructor(file: string) {
    fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    // Owner-only: the log reveals which files and tools carried secrets.
    this.fd = fs.openSync(file, "a", 0o600);
  }

  fingerprint = (value: string): string =>
    createHmac("sha256", this.key).update(value).digest("hex").slice(0, 16);

  write(e: AuditEvent): void {
    // Synchronous so nothing is lost if the proxy exits right after.
    fs.writeSync(this.fd, JSON.stringify({ ts: new Date().toISOString(), ...e }) + "\n");
  }

  close(): void {
    try {
      fs.closeSync(this.fd);
    } catch {
      /* already closed */
    }
  }
}
