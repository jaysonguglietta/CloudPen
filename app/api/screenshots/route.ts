import { requireCapability } from "../../../lib/security/authorization";
import { enforceScreenshotUploadRequest, safeApiError } from "../../../lib/security/request";
import { createScreenshotEvidence, listScreenshotEvidence, ValidationError } from "../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const user = await requireCapability("read");
    const url = new URL(request.url);
    const screenshots = await listScreenshotEvidence(user, {
      frameworkId: url.searchParams.get("framework") ?? undefined,
      controlId: url.searchParams.get("control") ?? undefined,
      query: url.searchParams.get("q") ?? undefined,
    });
    return Response.json({ screenshots }, { headers: { "cache-control": "no-store, private" } });
  } catch (error) {
    return safeApiError(error);
  }
}

export async function POST(request: Request) {
  try {
    enforceScreenshotUploadRequest(request);
    const user = await requireCapability("capture");
    const form = await request.formData();
    if (form.get("authorized") !== "true") {
      throw new ValidationError("You must confirm that you are authorized to capture the selected screen.");
    }
    const image = form.get("image");
    if (!(image instanceof Blob) || image.size < 1 || image.size > 12 * 1024 * 1024) {
      throw new ValidationError("A PNG screenshot no larger than 12 MiB is required.");
    }
    if (image.type && image.type !== "image/png") throw new ValidationError("Screenshot uploads must be PNG images.");
    const bannerPosition = String(form.get("bannerPosition") ?? "");
    if (bannerPosition !== "top" && bannerPosition !== "bottom") throw new ValidationError("Unsupported banner position.");
    const screenshot = await createScreenshotEvidence(user, {
      frameworkId: String(form.get("frameworkId") ?? ""),
      controlId: String(form.get("controlId") ?? ""),
      title: String(form.get("title") ?? ""),
      notes: String(form.get("notes") ?? ""),
      customName: String(form.get("customName") ?? ""),
      bannerPosition,
      includeTimestamp: form.get("includeTimestamp") === "true",
      includeActor: form.get("includeActor") === "true",
      capturedAt: String(form.get("capturedAt") ?? ""),
    }, new Uint8Array(await image.arrayBuffer()));
    return Response.json({ screenshot }, {
      status: 201,
      headers: { "cache-control": "no-store, private", location: screenshot.contentUrl },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
