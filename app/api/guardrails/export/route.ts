import { requireCapability } from "../../../../lib/security/authorization";
import { safeApiError } from "../../../../lib/security/request";
import { exportGuardrailPolicy } from "../../../../lib/server/control-plane";

export async function GET() {
  try {
    const user = await requireCapability("read");
    return Response.json(await exportGuardrailPolicy(user), {
      headers: {
        "cache-control": "no-store, private",
        "content-disposition": "attachment; filename=cloudpen-guardrails.json",
      },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
