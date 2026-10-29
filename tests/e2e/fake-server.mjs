// Scripted stdio "MCP server" for transport edge cases a real server can't
// trigger on demand. Mode chosen by argv[2]. Fake key assembled from parts.
const KEY = "AKIA" + "4HKQ7R2ZXM3PLQ8W";
const mode = process.argv[2];
const line = (o) => Buffer.from(JSON.stringify(o) + "\n", "utf8");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (mode === "utf8-split") {
  // One message with multi-byte characters, written in 1-byte chunks so
  // characters are split across 'data' events.
  const buf = line({ jsonrpc: "2.0", id: 1, result: { text: "café — 日本語 — 🚀 — naïve résumé" } });
  for (const b of buf) { process.stdout.write(Buffer.from([b])); await sleep(1); }
} else if (mode === "big") {
  // One very large message (N MB) written in 64 KB chunks.
  const mb = Number(process.argv[3] ?? 10);
  const payload = "lorem ipsum dolor sit amet ".repeat(Math.ceil((mb * 1024 * 1024) / 27)).slice(0, mb * 1024 * 1024);
  const buf = line({ jsonrpc: "2.0", id: 1, result: { text: payload + " key=" + KEY } });
  for (let i = 0; i < buf.length; i += 65536) process.stdout.write(buf.subarray(i, i + 65536));
} else if (mode === "exit-fast") {
  // Write the final response and exit immediately (common in short-lived servers).
  process.stdout.write(line({ jsonrpc: "2.0", id: 1, result: { text: "last words " + KEY } }));
  process.exit(0);
} else if (mode === "no-newline") {
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { text: "no trailing newline" } }));
  setTimeout(() => process.exit(0), 50);
} else if (mode === "crash") {
  process.stdout.write(line({ jsonrpc: "2.0", id: 1, result: { text: "before crash" } }));
  setTimeout(() => process.exit(3), 50);
} else if (mode === "echo") {
  // Echo server: waits for stdin, replies per line, exits ONLY on stdin EOF.
  let buf = "";
  process.stdin.on("data", (c) => {
    buf += c;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, i); buf = buf.slice(i + 1);
      const m = JSON.parse(l);
      process.stdout.write(line({ jsonrpc: "2.0", id: m.id, result: { got: m.params } }));
    }
  });
  process.stdin.on("end", () => { process.stderr.write("[echo] stdin EOF, exiting\n"); process.exit(0); });
} else if (mode === "log-noise") {
  // Server that (incorrectly) prints plain log lines to stdout between messages.
  process.stdout.write("Server starting with key " + KEY + "\n");
  process.stdout.write(line({ jsonrpc: "2.0", id: 1, result: { text: "ok" } }));
  setTimeout(() => process.exit(0), 50);
} else if (mode === "string-id") {
  // Response whose JSON-RPC id is a string the client chose (e.g. Date.now()-based).
  process.stdout.write(line({ jsonrpc: "2.0", id: process.argv[3], result: { text: "ok" } }));
  setTimeout(() => process.exit(0), 50);
} else if (mode === "structured") {
  // MCP structuredContent where the secret value sits under a field name.
  process.stdout.write(line({ jsonrpc: "2.0", id: 1, result: {
    content: [{ type: "text", text: "{\"db_password\": \"Winter2026Prod!Acme\"}" }],
    structuredContent: { user: "acme_admin", db_password: "Winter2026Prod!Acme", api_key: "x7Qm2vL9tW4nB8cF3hJ6sD1gY5zA" },
  } }));
  setTimeout(() => process.exit(0), 50);
}
if (mode === "big-alive") {
  const mb = Number(process.argv[3] ?? 10);
  const payload = "lorem ipsum dolor sit amet ".repeat(Math.ceil((mb * 1024 * 1024) / 27)).slice(0, mb * 1024 * 1024);
  const buf = line({ jsonrpc: "2.0", id: 1, result: { text: payload + " key=" + KEY } });
  for (let i = 0; i < buf.length; i += 65536) process.stdout.write(buf.subarray(i, i + 65536));
  setInterval(() => {}, 1000); // stay alive like a real server
}
if (mode === "progress") {
  // Server -> client progress notification; the token must come back unchanged.
  process.stdout.write(line({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "tok_8f3kQ9mZ2vL7xR4t", progress: 1, total: 2 } }));
  setTimeout(() => process.exit(0), 50);
}
