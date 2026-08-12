import { canonicalJson, sha256Base64Url } from "./canonical";
import type { RuntimeBindings } from "./runtime";

export type SecurityEvent = {
  schema: "cloudpen.security-event.v1";
  eventId: string;
  timestamp: string;
  requestId: string | null;
  category: string;
  outcome: "allowed" | "denied" | "alert";
  [key: string]: string | number | boolean | null;
};

export async function emitSecurityEvent(event: SecurityEvent, env: RuntimeBindings): Promise<void> {
  console.log(canonicalJson(event));
  const destination = siemConfiguration(env);
  if (!destination) {
    if (env.CLOUDPEN_PRODUCTION_MODE === "1") await enqueue(event, env.DB, "siem_configuration_missing");
    return;
  }
  const delivered = await postEvent(event, destination);
  if (!delivered.ok) {
    await enqueue(event, env.DB, delivered.error);
    return;
  }
  await flushDueEvents(env.DB, destination);
}

function siemConfiguration(env: RuntimeBindings): { url: string; token: string } | null {
  const rawUrl = env.CLOUDPEN_SIEM_URL?.trim();
  const token = env.CLOUDPEN_SIEM_TOKEN?.trim();
  if (!rawUrl && !token) return null;
  if (!rawUrl || !token || token.length < 32) return null;
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/v1/events") return null;
    return { url: url.href, token };
  } catch {
    return null;
  }
}

async function postEvent(
  event: SecurityEvent,
  destination: { url: string; token: string },
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const body = canonicalJson(event);
    const response = await fetch(destination.url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${destination.token}`,
        "content-type": "application/json",
        "x-cloudpen-event-digest": await sha256Base64Url(body),
      },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(3_000),
    });
    return response.ok ? { ok: true } : { ok: false, error: `siem_http_${response.status}` };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? `siem_${error.name.toLowerCase()}` : "siem_network_error" };
  }
}

async function enqueue(event: SecurityEvent, db: D1Database | undefined, error: string): Promise<void> {
  if (!db) return;
  const body = canonicalJson(event);
  try {
    const result = await db.prepare(`INSERT INTO security_event_outbox
        (id, event_json, event_digest, attempts, next_attempt_at, last_error, delivered_at, created_at)
        SELECT ?, ?, ?, 0, ?, ?, NULL, ?
        WHERE (SELECT COUNT(*) FROM security_event_outbox WHERE delivered_at IS NULL) < 10000
        ON CONFLICT(id) DO UPDATE SET last_error = excluded.last_error`)
      .bind(event.eventId, body, await sha256Base64Url(body), Math.floor(Date.now() / 1000) + 30,
        safeError(error), new Date().toISOString())
      .run();
    if (!result.meta.changes) console.error(canonicalJson({
      schema: "cloudpen.telemetry-failure.v1",
      eventId: event.eventId,
      category: "siem_outbox_capacity_reached",
    }));
  } catch (queueError) {
    console.error(canonicalJson({
      schema: "cloudpen.telemetry-failure.v1",
      eventId: event.eventId,
      category: "siem_outbox_failure",
      error: queueError instanceof Error ? queueError.name : "UnknownError",
    }));
  }
}

async function flushDueEvents(db: D1Database | undefined, destination: { url: string; token: string }): Promise<void> {
  if (!db) return;
  const now = Math.floor(Date.now() / 1000);
  const due = await db.prepare(`SELECT id, event_json, attempts FROM security_event_outbox
      WHERE delivered_at IS NULL AND next_attempt_at <= ? ORDER BY created_at LIMIT 5`)
    .bind(now).all<{ id: string; event_json: string; attempts: number }>();
  for (const row of due.results) {
    let event: SecurityEvent;
    try { event = JSON.parse(row.event_json) as SecurityEvent; } catch {
      await db.prepare("UPDATE security_event_outbox SET attempts = attempts + 1, last_error = 'invalid_event_json', next_attempt_at = ? WHERE id = ?")
        .bind(now + 86_400, row.id).run();
      continue;
    }
    const result = await postEvent(event, destination);
    if (result.ok) {
      await db.prepare("UPDATE security_event_outbox SET delivered_at = ?, last_error = NULL WHERE id = ? AND delivered_at IS NULL")
        .bind(new Date().toISOString(), row.id).run();
    } else {
      const attempts = Math.min(Number(row.attempts) + 1, 16);
      const delay = Math.min(86_400, 30 * 2 ** attempts);
      await db.prepare(`UPDATE security_event_outbox SET attempts = ?, last_error = ?, next_attempt_at = ?
          WHERE id = ? AND delivered_at IS NULL`)
        .bind(attempts, safeError(result.error), now + delay, row.id).run();
    }
  }
}

function safeError(value: string): string {
  return value.replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 120);
}
