import { requireCapability } from "../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../lib/security/request";
import { recordConnectorRequest } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("connect");
    const body = await readJsonObject(request);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const accountId = typeof body.accountId === "string" ? body.accountId : "";
    const externalId = typeof body.externalId === "string" ? body.externalId.trim() : "";
    const externalIdPayload = externalId.startsWith("cpv1_") ? externalId.slice(5) : "";
    if (name.length < 2 || name.length > 80 || !/^\d{12}$/.test(accountId) ||
        !/^[A-Za-z0-9_-]{43}$/.test(externalIdPayload) || new Set(externalIdPayload).size < 12) {
      return Response.json({ error: "Use a CloudPen-generated 256-bit External ID." }, { status: 400 });
    }
    const result = await recordConnectorRequest(user, { name, accountId, externalId });
    return Response.json(result, { status: 202, headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
