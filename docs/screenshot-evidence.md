# Screenshot evidence workflow

CloudPen can capture one authorized screen, window, or browser tab frame and map it to a compliance control. The feature is intended for evidence collection, not surveillance or background recording.

## Supported workflow

1. Open **Evidence capture** and select **Capture screenshot**.
2. Choose a compliance area and its dependent control number.
3. Enter a descriptive evidence title, safe custom filename portion, and optional collection notes.
4. Choose a top or bottom banner and whether the UTC timestamp and collector identity appear. The framework and control number always appear.
5. Confirm collection authorization and review the selected surface for secrets, personal data, and unrelated content.
6. Use the browser picker to select a screen, window, or tab. CloudPen takes one frame, stops every media track, stamps the frame in the browser, and uploads the PNG.
7. Search the evidence library with the same framework and control dropdowns, or use title/filename/notes text search.

Browsers require a secure context for screen capture. Loopback origins such as `http://127.0.0.1` qualify; non-loopback deployments require HTTPS. The operating system or browser can deny capture, and cancellation stores nothing.

## Naming and folder rules

CloudPen derives names rather than accepting paths from the client.

```text
Logical folder: <framework>/<control>/<YYYY>/<MM>/
Filename:       <FRAMEWORK>_<control>_<UTC timestamp>_<custom name>.png
```

Example:

```text
hipaa/164.312-a-1/2026/08/
HIPAA_164.312-a-1_20260811T143000Z_privileged-access-review.png
```

Unsafe path characters, whitespace runs, and control punctuation are normalized. The actual R2 object key also contains the workspace and immutable screenshot record ID to prevent collisions. A browser download receives the generated filename; browsers cannot create the displayed server-side folder tree on the user's computer.

## Compliance catalog

The current built-in catalog contains curated evidence-relevant references for:

- HIPAA Security Rule, 45 CFR Part 164;
- PCI DSS v4.0.1;
- FedRAMP Rev. 5 / NIST SP 800-53 Rev. 5;
- SOC 2 Trust Services Criteria;
- ISO/IEC 27001:2022 Annex A;
- NIST Cybersecurity Framework 2.0.

The catalog is a product taxonomy, not a certification opinion and not an exhaustive substitute for licensed or authoritative standards material. Control owners must verify the applicable version, baseline, implementation statement, and evidence requirements. A future catalog service or OSCAL import should replace the curated list when complete framework coverage and customer-defined overlays are required.

## Banner contents

Every PNG banner contains:

- framework short label;
- control number and control title;
- evidence title and custom filename portion.

The collector can additionally show the UTC capture timestamp and authenticated email. Banner rendering occurs before upload, so the stored object and optional local download are the same stamped bytes.

## Storage and retrieval

- D1 stores workspace-scoped framework/control metadata, display settings, logical path, dimensions, size, digest, actor, and timestamps.
- Private R2 stores the PNG body. There is no public bucket URL.
- Content is served only through an authenticated `read` route and is marked `private, no-store` with MIME sniffing disabled.
- Admins, operators, and reviewers can capture. Viewers can search, view, and download existing evidence.
- Search uses prepared D1 queries and returns at most 100 newest matches.
- Each creation is appended to the workspace audit chain.

## Collection safety

- Capture only systems and data within written authorization.
- Prefer a single application window or browser tab over an entire display.
- Close password managers, messaging windows, terminals with tokens, personal tabs, and unrelated customer records before opening the browser picker.
- Do not rely on the banner as redaction. Redact or remove sensitive content at the source before capture.
- Treat downloaded copies as confidential evidence and apply endpoint retention/encryption policy.
- If capture is denied, cancelled, malformed, over 12 MiB, over 12,000 pixels on an axis, or over 60 megapixels, no D1 evidence row is retained.

## Current limitations

- Automated redaction, OCR, annotation, duplicate detection, legal hold, retention expiry, bulk export, and evidence approval are not implemented.
- Control lists are curated rather than exhaustive and do not yet support organization-defined mappings.
- The screenshot SHA-256 digest detects accidental or unauthorized byte changes but is not an independent signature or timestamp authority.
- Local Wrangler R2 is development storage. Deleting `.wrangler/state` removes local evidence and metadata.
