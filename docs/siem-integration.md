# SIEM integration contract

CloudPen posts canonical `cloudpen.security-event.v1` JSON to the exact configured HTTPS `/v1/events` endpoint with a bearer credential and `X-CloudPen-Event-Digest` SHA-256 base64url digest. Redirects are rejected and requests time out after three seconds. The collector must return any `2xx` only after durable acceptance.

Events include a random event ID, timestamp, request correlation ID, normalized route template, method, category, outcome, status, duration, capability class, role, truncated hash of the actor email, and local-mode flag. Query strings, bodies, raw email, evidence values, External IDs, tokens, credentials, signing material, and cloud response payloads are excluded.

Delivery failures enter `security_event_outbox`. Successful future deliveries opportunistically retry due records in bounded batches with exponential backoff. Undelivered records never expire automatically. Delivered queue metadata is eligible for deletion after seven days unless a legal hold is active.

The independent collector must validate TLS, bearer credential, content type, schema allowlist, event ID uniqueness, timestamp skew, and body digest; rate-limit safely; store events immutably under separate administration; and alert on authorization, cross-origin, body-size, rate-limit, internal, identity-origin, audit-verification, signer, local-mode, and delivery-backlog signals. Never enable body capture at an upstream proxy.

Production acceptance evidence includes a synthetic allowed request, each denial class, simulated collector outage, queued event, successful retry, duplicate handling, alert receipt, token rotation, and retention/legal-hold behavior.

The deployable reference receiver in `infra/aws-siem-collector` implements this contract with a generated Secrets Manager token, a throttled HTTP API, strict schema/digest validation, S3 event-ID deduplication, and a private S3 Object Lock `COMPLIANCE` archive. Deploy it under a security-operations administration boundary; CloudPen receives only its write credential and has no archive read or delete capability.
