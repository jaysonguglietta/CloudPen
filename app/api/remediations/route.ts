import { requireCapability } from "../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../lib/security/request";
import { createRemediation } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("plan");
    const body = await readJsonObject(request);
    const pathId = typeof body.pathId === "string" ? body.pathId : "";
    const owner = typeof body.owner === "string" ? body.owner.trim() : "";
    const dueAt = typeof body.dueAt === "string" ? body.dueAt : "";
    const due = new Date(dueAt);
    if (!/^CP-\d{4}$/.test(pathId) || owner.length < 2 || owner.length > 100 || Number.isNaN(due.valueOf()) || due <= new Date()) {
      return Response.json({ error: "A valid path, owner, and future due date are required." }, { status: 400 });
    }
    return Response.json({ remediation: await createRemediation(user, { pathId, owner, dueAt: due.toISOString() }) }, {
      status: 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
