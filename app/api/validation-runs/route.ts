import { requireCapability } from "../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../lib/security/request";
import { createValidationPlan, listValidationRuns } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const user = await requireCapability("read");
    return Response.json({ runs: await listValidationRuns(user) }, {
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("plan");
    const body = await readJsonObject(request);
    const attackPathId = typeof body.attackPathId === "string" ? body.attackPathId : "";
    const mode = body.mode === "Read-only" || body.mode === "Active canary" ? body.mode : null;
    const acknowledged = body.acknowledged === true;
    if (!/^CP-\d{4}$/.test(attackPathId) || !mode) {
      return Response.json({ error: "A valid attackPathId and mode are required." }, { status: 400 });
    }
    const result = await createValidationPlan(user, { attackPathId, mode, acknowledged });
    return Response.json(result, { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
