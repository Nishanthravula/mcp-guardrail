/**
 * Detection rules for secrets and PII.
 *
 * Design notes:
 * - Rules are ordered by specificity. When two rules match at the same start
 *   position, the longer match wins; on a tie, the earlier rule wins.
 * - Every pattern is written to run in linear time on adversarial input:
 *   repetition is bounded, and patterns that could start inside a long run
 *   of matching characters are anchored with a lookbehind so they only start
 *   at the beginning of the run. `tests/redos.test.ts` enforces this.
 * - `quickCheck` is a cheap substring test that lets a rule skip strings that
 *   cannot possibly match (and bounds the cost of a few rules).
 * - `group` redacts only one capture group (e.g. the value in `NAME=value`).
 * - `validate` is a secondary check (Luhn, entropy, node:net parsing) to keep
 *   false positives down.
 */
import { isIPv4, isIPv6 } from "node:net";

export interface MatchContext {
  /** The full regex match (may be wider than the redacted span). */
  match: string;
  /** The whole string being scanned. */
  input: string;
  /** Start offset of the redacted span in `input`. */
  index: number;
}

export interface DetectionRule {
  id: string;
  /** Human-readable label used in the redaction placeholder. */
  label: string;
  category: "secret" | "pii";
  /** Must have the `g` flag. Add `d` when using `group`. */
  pattern: RegExp;
  /** Redact only this capture group instead of the whole match. */
  group?: number;
  /** Cheap pre-filter: return false to skip this rule for the whole string. */
  quickCheck?: (input: string) => boolean;
  /** Secondary check on the redacted text. Return false to reject. */
  validate?: (value: string, ctx: MatchContext) => boolean;
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
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

/**
 * True when the digits carry a real card-network prefix (IIN) and a length
 * that network issues. Cuts most false positives from Luhn alone (roughly 1
 * in 10 random digit strings pass Luhn: timestamps, order ids, etc.).
 */
export function cardBrandValid(s: string): boolean {
  const d = s.replace(/[\s-]/g, "");
  const n = d.length;
  const p2 = Number(d.slice(0, 2));
  const p3 = Number(d.slice(0, 3));
  const p4 = Number(d.slice(0, 4));
  const p6 = Number(d.slice(0, 6));
  if (d[0] === "4") return n === 13 || n === 16 || n === 19; // Visa
  if ((p2 >= 51 && p2 <= 55) || (p4 >= 2221 && p4 <= 2720)) return n === 16; // Mastercard
  if (p2 === 34 || p2 === 37) return n === 15; // Amex
  if (p4 === 6011 || p2 === 65 || (p3 >= 644 && p3 <= 649) || (p6 >= 622126 && p6 <= 622925))
    return n >= 16 && n <= 19; // Discover
  if (p2 === 36 || p2 === 38 || (p3 >= 300 && p3 <= 305)) return n === 14 || n === 16; // Diners
  if (p4 >= 3528 && p4 <= 3589) return n >= 16 && n <= 19; // JCB
  if (p2 === 62) return n >= 16 && n <= 19; // UnionPay
  return false;
}

/** Values that are clearly placeholders/references, not secrets. */
export function isPlaceholderValue(v: string): boolean {
  const t = v.trim();
  return (
    t.length === 0 ||
    t.startsWith("[REDACTED") ||
    /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(t) || // $VAR / ${VAR}
    /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(t) || // %VAR%
    /^\{\{.*\}\}$/.test(t) || // {{ template }}
    /^<[^<>]*>$/.test(t) || // <your-token-here>
    /^\*+$/.test(t) ||
    /^x{3,}$/i.test(t) ||
    /^(?:process\.env|os\.environ|env)\b/.test(t) ||
    /^(?:true|false|null|none|nil|undefined|required|optional)$/i.test(t)
  );
}

const SENSITIVE_NAME =
  "(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|" +
  "auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?key|" +
  "password|passwd|passphrase|pwd|secret|token|credentials?)";

/** Name suffixes that mean "metadata about a secret", not the secret itself. */
const NON_SECRET_SUFFIX =
  /(?:^|[_.-])(?:url|uri|endpoint|type|count|limit|file|path|name|header|expiry|expires?|ttl|length|len|min|max|policy|prefix|hint|field)$/i;

/**
 * Opaque protocol handles the model or client must be able to pass back
 * unchanged: pagination cursors and MCP progress tokens.
 */
const PAGINATION_NAME =
  /(?:page|next|continuation|sync|pagination|cursor|start|progress)[_-]?token$/i;

/**
 * Object keys whose string values are treated as secrets regardless of their
 * shape (used by the key-aware walk over structured JSON).
 */
export function isSensitiveKey(key: string): boolean {
  const k = key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\s.-]+/g, "_")
    .toLowerCase();
  if (PAGINATION_NAME.test(k)) return false;
  return /(?:^|_)(?:api_?key|access_?key|secret_?key|private_?key|client_?secret|auth_?token|access_?token|refresh_?token|id_?token|session_?key|session_?secret|password|passwd|passphrase|pwd|secret|token|credentials?|authorization|cookie|set_cookie)$/.test(
    k,
  );
}

const IN_URL = /(?<=\b[a-z][a-z0-9+.-]{1,20}:\/\/)/.source;

export const DEFAULT_RULES: DetectionRule[] = [
  // ---- Crypto material ----
  {
    id: "private-key-block",
    label: "PRIVATE_KEY",
    category: "secret",
    // The body may not contain "-----", so the scan from each BEGIN stops at
    // the very next marker: many BEGIN headers without an END stay linear.
    // Real PEM / OpenSSH / PGP bodies (base64 + headers like DEK-Info) never
    // contain five dashes. 32 KB covers RSA-8192 and large PGP blocks.
    pattern:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:[^-]|-(?!----)){0,32768}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    quickCheck: (s) => s.includes("PRIVATE KEY") && s.includes("-----END"),
  },

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
    pattern:
      /(?<![A-Za-z0-9])aws[A-Za-z0-9_.-]{0,20}?(?:secret|key)[A-Za-z0-9_.-]{0,20}["']?\s{0,3}[=:]\s{0,3}["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/dgi,
    group: 1,
    quickCheck: (s) => /aws/i.test(s),
  },
  {
    id: "anthropic-api-key",
    label: "ANTHROPIC_API_KEY",
    category: "secret",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,256}/g,
  },
  {
    id: "openai-api-key",
    label: "OPENAI_API_KEY",
    category: "secret",
    pattern: /(?<![A-Za-z0-9_-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,256}/g,
  },
  {
    id: "github-token",
    label: "GITHUB_TOKEN",
    category: "secret",
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: "github-fine-grained-pat",
    label: "GITHUB_PAT",
    category: "secret",
    pattern: /\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g,
  },
  {
    id: "slack-token",
    label: "SLACK_TOKEN",
    category: "secret",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,255}/g,
  },
  {
    id: "stripe-key",
    label: "STRIPE_KEY",
    category: "secret",
    pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,255}\b/g,
  },
  {
    id: "google-api-key",
    label: "GOOGLE_API_KEY",
    category: "secret",
    pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
  },
  {
    id: "jwt",
    label: "JWT",
    category: "secret",
    pattern: /\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}/g,
  },
  {
    id: "bearer-token",
    label: "BEARER_TOKEN",
    category: "secret",
    pattern: /\bBearer\s{1,3}([A-Za-z0-9._~+/-]{16,4096}=*)/dg,
    group: 1,
    validate: (v) => shannonEntropy(v) >= 3.0,
  },
  {
    id: "basic-auth-header",
    label: "BASIC_AUTH",
    category: "secret",
    pattern: /\bBasic\s{1,3}([A-Za-z0-9+/]{8,1024}={0,2})(?![A-Za-z0-9+/=])/dg,
    group: 1,
    validate: (v) => {
      try {
        return /^[\x20-\x7e]+:[\x20-\x7e]*$/.test(Buffer.from(v, "base64").toString("latin1"));
      } catch {
        return false;
      }
    },
  },

  // ---- Credentials in URLs ----
  {
    id: "connection-string-password",
    label: "CONNECTION_STRING_CREDENTIALS",
    category: "secret",
    // scheme://user:password@host — username may be empty (redis://:pw@host)
    pattern: new RegExp(IN_URL + /[^\s:@/]{0,64}:[^\s@/]{1,128}(?=@)/.source, "gi"),
    quickCheck: (s) => s.includes("://"),
  },
  {
    id: "url-token-userinfo",
    label: "URL_CREDENTIALS",
    category: "secret",
    // scheme://<token>@host — e.g. Sentry DSNs, https://<pat>@github.com
    pattern: new RegExp(IN_URL + /[A-Za-z0-9_-]{16,128}(?=@)/.source, "gi"),
    quickCheck: (s) => s.includes("://"),
    validate: (v) => shannonEntropy(v) >= 3.0,
  },

  // ---- Generic NAME=value secrets ----
  {
    id: "generic-assigned-secret",
    label: "SECRET",
    category: "secret",
    // DB_PASSWORD=..., "jwt_secret": "...", apiKey: ..., ACCESS_TOKEN=...
    pattern: new RegExp(
      "(?<![A-Za-z0-9])([A-Za-z0-9_.-]{0,40}?" +
        SENSITIVE_NAME +
        "(?:[_.-][A-Za-z0-9]{1,12}){0,2})[\"']?\\s{0,3}(?:=|:(?!//))\\s{0,3}[\"']?([^\\s\"'`,;<>(){}\\[\\]]{8,256})",
      "dgi",
    ),
    group: 2,
    quickCheck: (s) => s.includes("=") || s.includes(":"),
    validate: (v, ctx) => {
      const name = /^[A-Za-z0-9_.-]*/.exec(ctx.match)?.[0] ?? "";
      if (NON_SECRET_SUFFIX.test(name) || PAGINATION_NAME.test(name)) return false;
      if (isPlaceholderValue(v) || /^[a-z]+$/i.test(v) || /^\d+$/.test(v)) return false;
      if (/^https?:\/\//i.test(v)) return false;
      // Real secrets are printable ASCII; this skips UI strings in other scripts.
      if (/[^\x21-\x7e]/.test(v)) return false;
      // Code, not a value: options.clientSecret, z.string, this.req.secret, a?.b
      if (/^[A-Za-z_$][\w$]*(?:\??\.#?[A-Za-z_$][\w$]*)+$/.test(v)) return false;
      // snake_case identifiers (tokens.refresh_token handled above)
      if (/^[a-z]+(?:_[a-z]+)+$/i.test(v)) return false;
      // Filesystem paths: PWD=/Users/me, HOME=~/x, C:\\...
      if (/^(?:\/|~\/|\.{1,2}\/|[A-Za-z]:\\)/.test(v)) return false;
      // Short values can't reach high entropy, so scale the bar by length.
      const bar = Math.min(3.0, Math.log2(v.length) - 0.5);
      return shannonEntropy(v) >= bar;
    },
  },

  // ---- PII ----
  {
    id: "email",
    label: "EMAIL",
    category: "pii",
    // Local part only starts at the beginning of a run and is capped at 64
    // chars (RFC 5321); domain labels are bounded. Linear on any input.
    pattern:
      /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?){0,8}\.[A-Za-z]{2,24}\b/g,
    quickCheck: (s) => s.includes("@"),
    // user@host right after "scheme://" is URL userinfo, not an email.
    validate: (_m, ctx) => !ctx.input.slice(Math.max(0, ctx.index - 3), ctx.index).endsWith("://"),
  },
  {
    id: "ssn",
    label: "SSN",
    category: "pii",
    pattern: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g,
  },
  {
    id: "credit-card",
    label: "CREDIT_CARD",
    category: "pii",
    // Starts and ends on a digit (never swallows a separator); must pass Luhn
    // AND carry a real card-network prefix and length.
    pattern: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d])/g,
    validate: (v) => luhnValid(v) && cardBrandValid(v),
  },
  {
    id: "phone",
    label: "PHONE",
    category: "pii",
    // NANP with separators: (512) 555-0147, 512-555-0147, 512.555.0147,
    // +1 512 555 0147. E.164 international: +44 20 7946 0958.
    pattern:
      /(?<![\w+])(?:(?:\+?1[ .-]?)?(?:\([2-9]\d{2}\)\s?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}|\+(?:[2-9]\d{0,2})[ .-]\d{1,4}(?:[ .-]\d{2,4}){2,3})(?![\w-])/g,
  },
  {
    id: "ipv4",
    label: "IPV4",
    category: "pii",
    pattern: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)(?![\w-])/g,
    validate: (m, ctx) => {
      if (!isIPv4(m)) return false;
      if (m.startsWith("127.") || m === "0.0.0.0" || m.startsWith("255.")) return false;
      // Documentation ranges (RFC 5737): 192.0.2.x, 198.51.100.x, 203.0.113.x
      if (/^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./.test(m)) return false;
      // version strings: v4.2.0.1, ver=4.2.0.1, version: 4.2.0.1
      const before = ctx.input.slice(Math.max(0, ctx.index - 12), ctx.index);
      return !/(?:\bv|\bver(?:sion)?\s?[=:]?\s?)$/i.test(before);
    },
  },
  {
    id: "ipv6",
    label: "IPV6",
    category: "pii",
    // Candidate run of hex groups, then parsed by node:net. Only starts at
    // the beginning of a run, so long hex:colon strings stay linear.
    pattern:
      /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})(?![\w:.]?[\w:])/g,
    validate: (m) => {
      if (!isIPv6(m) || m === "::" || m === "::1") return false;
      // 2001:db8::/32 is reserved for documentation (RFC 3849).
      if (/^2001:0?db8:/i.test(m)) return false;
      const groups = m.split(":").filter(Boolean);
      // Skips MAC addresses (not IPv6), and short Foo::Bar code tokens.
      return groups.length >= 2 && groups.join("").length >= 4;
    },
  },
];
