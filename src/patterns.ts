/**
 * Detection rules for secrets and PII.
 *
 * Design notes:
 * - Patterns are ordered roughly by specificity; more specific rules run first
 *   so a value is labeled by its most precise category.
 * - Each rule can carry an optional `validate` post-check (e.g. Luhn for cards,
 *   entropy for generic tokens) to keep false positives down.
 */

export interface DetectionRule {
  id: string;
  /** Human-readable label used in the redaction placeholder. */
  label: string;
  category: "secret" | "pii";
  pattern: RegExp;
  /** Optional secondary check on the matched string. Return false to reject. */
  validate?: (match: string) => boolean;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Luhn checksum for credit-card-like number sequences. */
export function luhnValid(s: string): boolean {
  const digits = s.replace(/[\s-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export const DEFAULT_RULES: DetectionRule[] = [
  // ---- Cloud / vendor keys (high specificity) ----
  {
    id: "aws-access-key-id",
    label: "AWS_ACCESS_KEY_ID",
    category: "secret",
    pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  },
  {
    id: "aws-secret-access-key",
    label: "AWS_SECRET_ACCESS_KEY",
    category: "secret",
    // Assignment-context match: aws_secret_access_key = <40 base64ish chars>
    pattern:
      /(?<=aws.{0,20}(?:secret|key).{0,10}[=:]\s*["']?)[A-Za-z0-9/+=]{40}(?=["']?)/gi,
  },
  {
    id: "anthropic-api-key",
    label: "ANTHROPIC_API_KEY",
    category: "secret",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "openai-api-key",
    label: "OPENAI_API_KEY",
    category: "secret",
    pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: "github-token",
    label: "GITHUB_TOKEN",
    category: "secret",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    label: "GITHUB_PAT",
    category: "secret",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g,
  },
  {
    id: "slack-token",
    label: "SLACK_TOKEN",
    category: "secret",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  },
  {
    id: "stripe-key",
    label: "STRIPE_KEY",
    category: "secret",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
  },
  {
    id: "google-api-key",
    label: "GOOGLE_API_KEY",
    category: "secret",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    id: "jwt",
    label: "JWT",
    category: "secret",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    id: "private-key-block",
    label: "PRIVATE_KEY",
    category: "secret",
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
  },
  {
    id: "connection-string-password",
    label: "CONNECTION_STRING_CREDENTIALS",
    category: "secret",
    // scheme://user:password@host — redact the credentials portion
    pattern: /(?<=\b[a-z][a-z0-9+.-]{1,20}:\/\/)[^\s:@/]{1,64}:[^\s@/]{1,128}(?=@)/gi,
  },
  {
    id: "generic-assigned-secret",
    label: "SECRET",
    category: "secret",
    // key/token/secret/password = <value> — entropy-gated to limit false positives
    pattern:
      /(?<=\b(?:api[_-]?key|token|secret|passwd|password|auth)\b.{0,10}[=:]\s*["']?)[^\s"']{12,128}(?=["']?)/gi,
    validate: (m) =>
      shannonEntropy(m) >= 3.2 &&
      !/^[a-z]+$/i.test(m) &&
      !m.includes("REDACTED") &&
      !m.startsWith("["),
  },

  // ---- PII ----
  {
    id: "email",
    label: "EMAIL",
    category: "pii",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    id: "ssn",
    label: "SSN",
    category: "pii",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    id: "credit-card",
    label: "CREDIT_CARD",
    category: "pii",
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
    validate: luhnValid,
  },
  {
    id: "ipv4",
    label: "IPV4",
    category: "pii",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    // Skip common non-sensitive addresses
    validate: (m) =>
      !m.startsWith("127.") && m !== "0.0.0.0" && !m.startsWith("255."),
  },
  {
    id: "ipv6",
    label: "IPV6",
    category: "pii",
    pattern: /\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi,
    validate: (m) => m !== "::1" && m.includes(":"),
  },
];
