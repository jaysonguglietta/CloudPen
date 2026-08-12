import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { createLegalHold, getLifecycleStatus, releaseLegalHold, runLifecycleMaintenance } from "../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const user = await requireCapability("configure");
    return Response.json(await getLifecycleStatus(user), { headers: { "cache-control": "no-store, private" } });
  } catch (error) {
    return safeApiError(error);
  }
}

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("configure");
    const body = await readJsonObject(request);
    const action = typeof body.action === "string" ? body.action : "";
    const reason = typeof body.reason === "string" ? body.reason : "";
    if (action === "maintain") return Response.json(await runLifecycleMaintenance(user));
    if (action === "create-hold") return Response.json(await createLegalHold(user, reason), { status: 201 });
    if (action === "release-hold") {
      const id = typeof body.id === "string" ? body.id : "";
      return Response.json(await releaseLegalHold(user, id, reason));
    }
    return Response.json({ error: "Unsupported lifecycle action." }, { status: 400 });
  } catch (error) {
    return safeApiError(error);
  }
}
