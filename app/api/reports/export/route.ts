import { requireCapability } from "../../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../../lib/security/request";
import { createAssessmentReport } from "../../../../lib/server/control-plane";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const body = await readJsonObject(request);
    if (Object.keys(body).length !== 0) return Response.json({ error: "Assessment export does not accept request fields." }, { status: 400 });
    const user = await requireCapability("read");
    return Response.json(await createAssessmentReport(user), {
      headers: {
        "cache-control": "no-store, private",
        "content-disposition": "attachment; filename=cloudpen-assessment.json",
      },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
