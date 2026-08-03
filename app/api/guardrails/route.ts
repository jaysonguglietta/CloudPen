import { requireCapability } from "../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../lib/security/request";
import { getGuardrailPolicy, updateGuardrailPolicy } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const user = await requireCapability("read");
    return Response.json({ policy: await getGuardrailPolicy(user) }, { headers: { "cache-control": "no-store, private" } });
  } catch (error) {
    return safeApiError(error);
  }
}

export async function PATCH(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("configure");
    const body = await readJsonObject(request);
    const allowed = ["requireApproval", "canaryOnly", "redactEvidence", "cleanupRequired"] as const;
    const patch: Record<string, boolean> = {};
    for (const key of allowed) {
      if (key in body) {
        if (typeof body[key] !== "boolean") return Response.json({ error: `${key} must be boolean.` }, { status: 400 });
        patch[key] = body[key] as boolean;
      }
    }
    if (Object.keys(patch).length !== 1) {
      return Response.json({ error: "Exactly one supported guardrail setting may be changed per request." }, { status: 400 });
    }
    return Response.json({ policy: await updateGuardrailPolicy(user, patch) }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
