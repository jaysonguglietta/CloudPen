import { requireCapability } from "../../../../lib/security/authorization";
import { safeApiError } from "../../../../lib/security/request";
import { createEvidencePackage } from "../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, { params }: { params: Promise<{ pathId: string }> }) {
  try {
    const user = await requireCapability("read");
    const { pathId } = await params;
    if (!/^CP-\d{4}$/.test(pathId)) return Response.json({ error: "Invalid evidence path." }, { status: 400 });
    const report = await createEvidencePackage(user, pathId);
    return new Response(JSON.stringify(report, null, 2), {
      headers: {
        "cache-control": "no-store, private",
        "content-disposition": `attachment; filename="${pathId.toLowerCase()}-evidence.json"`,
        "content-type": "application/json; charset=utf-8",
        "x-content-type-options": "nosniff",
      },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
