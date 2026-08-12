import type { AttackPath } from "../cloudpen-data";

const replacements: Array<[RegExp, string]> = [
  [/\bA(?:KI|SI)A[0-9A-Z]{16}\b/g, "[REDACTED_AWS_ACCESS_KEY]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED_TOKEN]"],
  [/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, "[REDACTED_JWT]"],
  [/-----BEGIN [^-\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^-\r\n]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*["']?[^\s"',;]+/gi, "$1=[REDACTED]"],
  [/(https?:\/\/)[^\s/:@]+:[^\s/@]+@/gi, "$1[REDACTED_CREDENTIALS]@"],
];

export function sanitizeAttackPathEvidence(path: AttackPath) {
  let redactedValues = 0;
  const clean = (value: string) => {
    let result = value;
    for (const [pattern, replacement] of replacements) {
      result = result.replace(pattern, () => {
        redactedValues += 1;
        return replacement;
      });
    }
    return result;
  };

  const evidence = {
    pathId: path.id,
    status: path.status,
    techniques: path.techniques.map(clean),
    observations: path.evidence.map(clean),
    rootCause: clean(path.rootCause),
    remediation: clean(path.remediation),
  };
  assertSanitized(evidence);
  return {
    evidence,
    redaction: {
      schema: "cloudpen.redaction.v1",
      applied: true,
      redactedValues,
      categories: ["credentials", "tokens", "private-keys", "embedded-url-credentials"],
    },
  };
}

function assertSanitized(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const [pattern] of replacements) {
    pattern.lastIndex = 0;
    if (pattern.test(serialized)) throw new Error("Evidence sanitization failed closed.");
  }
}
