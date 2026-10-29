#!/usr/bin/env node
/**
 * CLI: wrap any stdio MCP server with sanitization.
 *
 *   mcp-guardrail -- npx -y @modelcontextprotocol/server-filesystem /path
 *
 * Flags (before the `--`):
 *   --both                 also block requests that would send a secret to the server
 *   --allow-placeholders   let requests containing "[REDACTED:...]" through (not recommended)
 *   --max-string <n>       truncate string values longer than n characters
 *   --disable <ids>        comma-separated rule ids to disable
 *   --quiet                suppress stderr redaction logs
 */
import { GuardrailProxy } from "./proxy.js";

function fail(msg: string): never {
  process.stderr.write(`mcp-guardrail: ${msg}\n`);
  process.exit(2);
}

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
if (sep === -1 || sep === argv.length - 1) {
  fail(
    "usage: mcp-guardrail [--both] [--allow-placeholders] [--max-string N] [--disable id1,id2] [--quiet] -- <command> [args...]",
  );
}

const flags = argv.slice(0, sep);
const cmd = argv.slice(sep + 1);

let direction: "responses" | "both" = "responses";
let maxStringLength = 0;
let disable: string[] = [];
let logToStderr = true;
let blockPlaceholders = true;

for (let i = 0; i < flags.length; i++) {
  switch (flags[i]) {
    case "--both":
      direction = "both";
      break;
    case "--allow-placeholders":
      blockPlaceholders = false;
      break;
    case "--max-string":
      maxStringLength = parseInt(flags[++i] ?? "", 10);
      if (Number.isNaN(maxStringLength) || maxStringLength < 0)
        fail("--max-string requires a non-negative number");
      break;
    case "--disable":
      disable = (flags[++i] ?? "").split(",").filter(Boolean);
      break;
    case "--quiet":
      logToStderr = false;
      break;
    default:
      fail(`unknown flag: ${flags[i]}`);
  }
}

new GuardrailProxy({
  command: cmd[0],
  args: cmd.slice(1),
  direction,
  maxStringLength,
  disable,
  logToStderr,
  blockPlaceholders,
}).start();
