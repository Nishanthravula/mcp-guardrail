export { Sanitizer, DEFAULT_RULES, SENSITIVE_KEY_RULE } from "./sanitizer.js";
export type {
  SanitizerOptions,
  SanitizeResult,
  RedactionDetail,
  Finding,
  DetectionRule,
  MatchContext,
} from "./sanitizer.js";
export { GuardrailProxy, LineBuffer } from "./proxy.js";
export type { ProxyOptions } from "./proxy.js";
export {
  loadConfig,
  validateConfig,
  compileRules,
  findSlowRules,
  ConfigError,
} from "./config.js";
export type { GuardrailConfig, CustomRuleConfig, ToolPolicy } from "./config.js";
export { scanText, scanPaths } from "./scan.js";
export type { ScanFinding, ScanReport } from "./scan.js";
export {
  shannonEntropy,
  luhnValid,
  cardBrandValid,
  isSensitiveKey,
  isPlaceholderValue,
} from "./patterns.js";
export { VERSION } from "./version.js";
