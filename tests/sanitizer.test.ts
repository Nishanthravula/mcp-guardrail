import { test } from "node:test";
import assert from "node:assert/strict";
import { Sanitizer, luhnValid, shannonEntropy } from "../src/index.js";

const s = new Sanitizer();

function redacted(input: string): string {
  return s.sanitizeString(input).output;
}

test("AWS access key id", () => {
  const out = redacted("key is AKIAIOSFODNN7EXAMPLE ok");
  assert.match(out, /\[REDACTED:AWS_ACCESS_KEY_ID\]/);
  assert.ok(!out.includes("AKIAIOSFODNN7EXAMPLE"));
});

test("Anthropic API key", () => {
  const out = redacted("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx");
  assert.match(out, /\[REDACTED:ANTHROPIC_API_KEY\]/);
});

test("GitHub token", () => {
  const out = redacted("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
  assert.match(out, /\[REDACTED:GITHUB_TOKEN\]/);
});

test("JWT", () => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";
  const out = redacted(`Authorization: Bearer ${jwt}`);
  assert.match(out, /\[REDACTED:JWT\]/);
});

test("private key block", () => {
  const pem =
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...snip...\n-----END RSA PRIVATE KEY-----";
  assert.match(redacted(pem), /\[REDACTED:PRIVATE_KEY\]/);
});

test("connection string credentials", () => {
  const out = redacted("postgres://admin:hunter2secret@db.internal:5432/app");
  assert.ok(!out.includes("hunter2secret"));
  assert.match(out, /\[REDACTED:CONNECTION_STRING_CREDENTIALS\]/);
  // host survives
  assert.ok(out.includes("db.internal"));
});

test("email", () => {
  const out = redacted("contact jane.doe@example.com for access");
  assert.match(out, /\[REDACTED:EMAIL\]/);
});

test("SSN format", () => {
  assert.match(redacted("ssn: 123-45-6789"), /\[REDACTED:SSN\]/);
  // invalid area 000 not matched
  assert.ok(!redacted("000-12-3456").includes("REDACTED:SSN"));
});

test("credit card requires Luhn", () => {
  assert.ok(luhnValid("4111 1111 1111 1111"));
  assert.match(redacted("card 4111 1111 1111 1111"), /\[REDACTED:CREDIT_CARD\]/);
  // fails Luhn → untouched
  assert.ok(redacted("id 1234 5678 9012 3456").includes("1234 5678 9012 3456"));
});

test("ipv4 skips loopback", () => {
  assert.match(redacted("server at 10.1.2.3"), /\[REDACTED:IPV4\]/);
  assert.ok(redacted("localhost 127.0.0.1").includes("127.0.0.1"));
});

test("entropy-gated generic secret", () => {
  // high-entropy assigned value → redacted
  const hot = redacted('password = "x9K$mQ2#vL8pW4nR7t"');
  assert.ok(!hot.includes("x9K$mQ2#vL8pW4nR7t"));
  // plain english word → untouched (low entropy)
  const cold = redacted("password = changeme");
  assert.ok(cold.includes("changeme"));
});

test("deep object walk", () => {
  const input = {
    tool: "read_file",
    result: {
      content: [
        { type: "text", text: "AWS_KEY=AKIAIOSFODNN7EXAMPLE" },
        { type: "text", text: "safe text" },
      ],
    },
  };
  const { value, redactions } = s.sanitize(input);
  assert.ok(JSON.stringify(value).includes("[REDACTED:AWS_ACCESS_KEY_ID]"));
  assert.ok(!JSON.stringify(value).includes("AKIAIOSFODNN7EXAMPLE"));
  assert.equal(redactions.length, 1);
  assert.equal((value as typeof input).result.content[1].text, "safe text");
});

test("string truncation", () => {
  const capped = new Sanitizer({ maxStringLength: 10 });
  const { value, truncated } = capped.sanitize({ big: "a".repeat(50) });
  assert.equal(truncated, 1);
  assert.ok((value as { big: string }).big.startsWith("aaaaaaaaaa…[TRUNCATED"));
});

test("entropy sanity", () => {
  assert.ok(shannonEntropy("aaaa") < 1);
  assert.ok(shannonEntropy("x9K$mQ2#vL8pW4nR7t") > 3.5);
});
