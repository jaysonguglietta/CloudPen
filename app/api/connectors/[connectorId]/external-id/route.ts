import { requireCapability } from "../../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../../lib/security/request";
import { rotateConnectorExternalId } from "../../../../../lib/server/control-plane";

export async function POST(request: Request, { params }: { params: Promise<{ connectorId: string }> }) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("connect");
    const body = await readJsonObject(request);
    const externalId = typeof body.externalId === "string" ? body.externalId.trim() : "";
    const { connectorId } = await params;
    if (!/^CON-[A-Z0-9]{8}$/.test(connectorId)) {
      return Response.json({ error: "Invalid connector." }, { status: 400 });
    }
    await rotateConnectorExternalId(user, connectorId, externalId);
    return Response.json({ status: "rotation-recorded", externalIdStatus: "not-retained" }, {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
