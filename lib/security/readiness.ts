import "server-only";
import { productionRuntimeProblems, runtimeBindings } from "./runtime";

export type ReadinessCheck = {
  id: string;
  status: "pass" | "fail" | "warning";
  detail: string;
};

export function productionReadiness(): { ready: boolean; mode: "production" | "evaluation"; checks: ReadinessCheck[] } {
  const bindings = runtimeBindings();
  const production = bindings.CLOUDPEN_PRODUCTION_MODE === "1";
  const problems = new Set(productionRuntimeProblems(bindings));
  const checks: ReadinessCheck[] = [
    check("durable_database", !problems.has("durable_database"), "A durable D1 database binding is available."),
    check("canonical_https_origin", !problems.has("canonical_https_origin"), "The canonical application origin uses HTTPS."),
    check("local_mode_disabled", !problems.has("local_mode_disabled"), "Loopback development identity is disabled."),
    check("ephemeral_signer_disabled", !problems.has("ephemeral_signer_disabled"), "Ephemeral signing is disabled."),
    check("external_signer", !problems.has("external_signer"), "A constrained HTTPS signing endpoint is configured."),
    check("signer_token", !problems.has("signer_token"), "A high-entropy signer credential is configured."),
    check("signing_key_id", !problems.has("signing_key_id"), "A versioned signing key ID is configured."),
    check("signing_public_key", !problems.has("signing_public_key"), "A public RSA verification key is configured."),
    check("siem_endpoint", !problems.has("siem_endpoint"), "An independently administered SIEM endpoint is configured."),
    check("siem_token", !problems.has("siem_token"), "A high-entropy SIEM delivery credential is configured."),
  ];
  if (!production) {
    checks.unshift({ id: "production_mode", status: "warning", detail: "CLOUDPEN_PRODUCTION_MODE is not enabled; this is an evaluation deployment." });
  } else {
    checks.unshift(check("production_mode", true, "Production enforcement is enabled."));
  }
  return { ready: production && checks.every((item) => item.status === "pass"), mode: production ? "production" : "evaluation", checks };
}

function check(id: string, passed: boolean, detail: string): ReadinessCheck {
  return { id, status: passed ? "pass" : "fail", detail: passed ? detail : `${detail.replace(/\.$/, "")} is missing or invalid.` };
}
