import { requireCapability } from "../../../../lib/security/authorization";
import { productionReadiness } from "../../../../lib/security/readiness";
import { safeApiError } from "../../../../lib/security/request";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    await requireCapability("configure");
    const result = productionReadiness();
    return Response.json(result, {
      status: result.ready ? 200 : 503,
      headers: { "cache-control": "no-store, private" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
