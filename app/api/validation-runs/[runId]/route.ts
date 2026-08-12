import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { decideValidationRun } from "../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function PATCH(request: Request, { params }: { params: Promise<{ runId: string }> }) {
  try {
    enforceMutationRequest(request);
    const body = await readJsonObject(request);
    const decision = body.decision === "approve" || body.decision === "reject" || body.decision === "cancel" ? body.decision : null;
    const reason = typeof body.reason === "string" ? body.reason.trim() : "";
    if (!decision || reason.length < 4 || reason.length > 300) {
      return Response.json({ error: "A supported decision and a 4–300 character reason are required." }, { status: 400 });
    }
    const user = await requireCapability(decision === "cancel" ? "plan" : "approve");
    const { runId } = await params;
    if (!/^RUN-[A-Z0-9]{8}$/.test(runId)) return Response.json({ error: "Invalid run ID." }, { status: 400 });
    const result = await decideValidationRun(user, runId, decision, reason);
    return Response.json({ status: "updated", ...result }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
