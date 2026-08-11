import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { updateRemediation } from "../../../../lib/server/control-plane";
import type { RemediationRecord } from "../../../../lib/cloudpen-data";

const statuses: RemediationRecord["status"][] = ["Open", "In progress", "Risk accepted", "Ready to revalidate", "Closed"];

export async function PATCH(request: Request, { params }: { params: Promise<{ remediationId: string }> }) {
  try {
    enforceMutationRequest(request);
    const body = await readJsonObject(request);
    const status = typeof body.status === "string" && statuses.includes(body.status as RemediationRecord["status"])
      ? body.status as RemediationRecord["status"] : null;
    const version = typeof body.version === "number" && Number.isSafeInteger(body.version) && body.version > 0 ? body.version : null;
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    const riskAcceptanceExpiresAt = typeof body.riskAcceptanceExpiresAt === "string" ? body.riskAcceptanceExpiresAt : null;
    const revalidationEvidenceId = typeof body.revalidationEvidenceId === "string" ? body.revalidationEvidenceId : null;
    const { remediationId } = await params;
    if (!status || !version || reason.length < 8 || reason.length > 500 || !/^REM-[A-Z0-9]{8}$/.test(remediationId)) {
      return Response.json({ error: "A valid status, record version, and 8–500 character decision reason are required." }, { status: 400 });
    }
    if (status === "Risk accepted") {
      const expiry = riskAcceptanceExpiresAt ? new Date(riskAcceptanceExpiresAt) : null;
      const maximum = Date.now() + 365 * 86_400_000;
      if (!expiry || Number.isNaN(expiry.valueOf()) || expiry <= new Date() || expiry.valueOf() > maximum) {
        return Response.json({ error: "Risk acceptance requires an expiry within the next 365 days." }, { status: 400 });
      }
    }
    if (status === "Closed" && (!revalidationEvidenceId || !/^EV-[A-Z0-9]{8}$/.test(revalidationEvidenceId))) {
      return Response.json({ error: "Closure requires a valid revalidation evidence package ID." }, { status: 400 });
    }
    const capability = status === "Risk accepted" ? "accept-risk" : status === "Closed" ? "close-remediation" : "plan";
    const user = await requireCapability(capability);
    await updateRemediation(user, remediationId, { status, version, reason, riskAcceptanceExpiresAt, revalidationEvidenceId });
    return Response.json({ status: "updated" }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
