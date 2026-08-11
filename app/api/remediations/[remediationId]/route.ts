import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { updateRemediation } from "../../../../lib/server/control-plane";
import type { RemediationRecord } from "../../../../lib/cloudpen-data";

const statuses: RemediationRecord["status"][] = ["Open", "In progress", "Risk accepted", "Ready to revalidate", "Closed"];

export async function PATCH(request: Request, { params }: { params: Promise<{ remediationId: string }> }) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("plan");
    const body = await readJsonObject(request);
    const status = typeof body.status === "string" && statuses.includes(body.status as RemediationRecord["status"])
      ? body.status as RemediationRecord["status"] : null;
    const { remediationId } = await params;
    if (!status || !/^REM-[A-Z0-9]{8}$/.test(remediationId)) return Response.json({ error: "Invalid remediation update." }, { status: 400 });
    await updateRemediation(user, remediationId, { status });
    return Response.json({ status: "updated" }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
