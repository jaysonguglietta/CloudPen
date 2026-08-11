import { requireCapability } from "../../../lib/security/authorization";
import { safeApiError } from "../../../lib/security/request";
import { getControlPlaneSnapshot } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const user = await requireCapability("read");
    return Response.json(await getControlPlaneSnapshot(user), {
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
