import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { createWorkspaceBackup } from "../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    await readJsonObject(request);
    const user = await requireCapability("configure");
    const backup = await createWorkspaceBackup(user);
    const date = new Date().toISOString().slice(0, 10);
    return Response.json(backup, {
      headers: {
        "cache-control": "no-store",
        "content-disposition": `attachment; filename="cloudpen-${user.workspaceId}-backup-${date}.json"`,
      },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
