import { requireCapability } from "../../../../../lib/security/authorization";
import { enforceMutationRequest, safeApiError } from "../../../../../lib/security/request";
import { createDiscoveryPlan } from "../../../../../lib/server/control-plane";

export async function POST(request: Request, { params }: { params: Promise<{ connectorId: string }> }) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("connect");
    const { connectorId } = await params;
    if (!/^CON-[A-Z0-9]{8}$/.test(connectorId)) return Response.json({ error: "Invalid connector ID." }, { status: 400 });
    return Response.json(await createDiscoveryPlan(user, connectorId), { status: 202, headers: { "cache-control": "no-store" } });
  } catch (error) {
    return safeApiError(error);
  }
}
