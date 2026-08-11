import { requireCapability } from "../../../lib/security/authorization";
import { enforceMutationRequest, readJsonObject, safeApiError } from "../../../lib/security/request";
import { createRunnerEnrollment } from "../../../lib/server/control-plane";

export async function POST(request: Request) {
  try {
    enforceMutationRequest(request);
    const user = await requireCapability("enroll");
    const body = await readJsonObject(request);
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const fingerprint = typeof body.publicKeyFingerprint === "string" ? body.publicKeyFingerprint.trim() : "";
    if (name.length < 2 || name.length > 80 || !/^(sha256:)?[A-Fa-f0-9]{64}$/.test(fingerprint)) {
      return Response.json({ error: "A runner name and SHA-256 public-key fingerprint are required." }, { status: 400 });
    }
    return Response.json({ runner: await createRunnerEnrollment(user, { name, publicKeyFingerprint: fingerprint.toLowerCase() }) }, {
      status: 201,
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
