import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { createAuditAnchor } from "../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    await readJsonObject(request);
    const user = await requireCapability("configure");
    return Response.json(await createAuditAnchor(user), { status: 201, headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
