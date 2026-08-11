import { requireCapability } from "../../../../../lib/security/authorization";
import { safeApiError } from "../../../../../lib/security/request";
import { getScreenshotEvidenceContent } from "../../../../../lib/server/control-plane";

export const dynamic = "force-dynamic";

export async function GET(request: Request, { params }: { params: Promise<{ screenshotId: string }> }) {
  try {
    const user = await requireCapability("read");
    const { screenshotId } = await params;
    if (!/^SCR-[A-F0-9]{8}$/.test(screenshotId)) {
      return Response.json({ error: "Invalid screenshot evidence identifier." }, { status: 400 });
    }
    const { object, storedFilename, sha256Digest } = await getScreenshotEvidenceContent(user, screenshotId);
    const download = new URL(request.url).searchParams.get("download") === "1";
    const disposition = `${download ? "attachment" : "inline"}; filename="${storedFilename}"`;
    return new Response(await object.arrayBuffer(), {
      headers: {
        "cache-control": "no-store, private",
        "content-disposition": disposition,
        "content-type": "image/png",
        "content-length": String(object.size),
        "x-cloudpen-sha256": sha256Digest,
        "x-content-type-options": "nosniff",
      },
    });
  } catch (error) {
    return safeApiError(error);
  }
}
