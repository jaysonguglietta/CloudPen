"use client";

import { useEffect, useMemo, useState } from "react";
import type {
  AuditRecord,
  AttackPath,
  CloudAccount,
  CloudAsset,
  ConnectorRecord,
  ControlPlaneSnapshot,
  EvidenceRecord,
  RemediationRecord,
  RunnerRecord,
  ScreenshotEvidenceRecord,
  Severity,
  ValidationRun,
  ViewKey,
} from "../lib/cloudpen-data";
import { complianceFrameworks, controlFolderSegment, frameworkById, screenshotFilename } from "../lib/compliance-controls";

const severityRank: Record<Severity, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const navigation: Array<{ key: ViewKey; label: string; icon: string }> = [
  { key: "overview", label: "Exposure overview", icon: "⌂" },
  { key: "paths", label: "Attack paths", icon: "↗" },
  { key: "assets", label: "Assets & identities", icon: "◇" },
  { key: "runs", label: "Validation runs", icon: "▶" },
  { key: "connectors", label: "Cloud connectors", icon: "⛓" },
  { key: "remediation", label: "Remediation", icon: "✓" },
  { key: "screenshots", label: "Evidence capture", icon: "▣" },
  { key: "evidence", label: "Evidence & audit", icon: "▤" },
  { key: "reports", label: "Reports", icon: "▥" },
  { key: "administration", label: "Administration", icon: "⚙" },
  { key: "guardrails", label: "Guardrails", icon: "◈" },
];

const viewTitles: Record<ViewKey, { eyebrow: string; title: string; description: string }> = {
  overview: {
    eyebrow: "Northstar workspace",
    title: "Exposure overview",
    description: "Prioritize what an attacker can actually reach—not what a policy scanner merely flags.",
  },
  paths: {
    eyebrow: "Attack graph",
    title: "Attack paths",
    description: "Inspect evidence-backed identity and resource chains across connected accounts.",
  },
  assets: {
    eyebrow: "Cloud inventory",
    title: "Assets & identities",
    description: "Understand the resources that create, inherit, or concentrate exploitable access.",
  },
  runs: {
    eyebrow: "Execution history",
    title: "Validation runs",
    description: "Review authorized tests, outcomes, evidence, and immutable operator history.",
  },
  connectors: {
    eyebrow: "Cloud access",
    title: "Cloud connectors",
    description: "Manage customer-controlled, credential-free account enrollment and read-only discovery plans.",
  },
  remediation: {
    eyebrow: "Exposure reduction",
    title: "Remediation",
    description: "Assign validated root causes, track service levels, and prepare fixes for revalidation.",
  },
  screenshots: {
    eyebrow: "Compliance evidence",
    title: "Screenshot evidence",
    description: "Capture, stamp, organize, and retrieve screenshots by framework and control reference.",
  },
  evidence: {
    eyebrow: "Assurance records",
    title: "Evidence & audit",
    description: "Verify signed evidence packages and inspect the workspace's tamper-evident event chain.",
  },
  audit: {
    eyebrow: "Assurance records",
    title: "Audit history",
    description: "Inspect attributable control-plane changes and integrity-linked security events.",
  },
  reports: {
    eyebrow: "Assurance reporting",
    title: "Assessment reports",
    description: "Package exposure, remediation, and integrity results for engineering, leadership, and audit stakeholders.",
  },
  administration: {
    eyebrow: "Workspace controls",
    title: "Administration",
    description: "Review membership boundaries and stage non-executable customer-hosted runner enrollment.",
  },
  guardrails: {
    eyebrow: "Safety policy",
    title: "Execution guardrails",
    description: "Constrain every validation before a credential or cloud API operation is allowed.",
  },
};

function initials(value: string): string {
  return value.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "CP";
}

function formatBytes(value: number): string {
  if (value < 1024 * 1024) return `${Math.max(1, Math.round(value / 1024))} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function fitCanvasText(context: CanvasRenderingContext2D, value: string, maxWidth: number): string {
  if (context.measureText(value).width <= maxWidth) return value;
  let shortened = value;
  while (shortened.length > 1 && context.measureText(`${shortened}…`).width > maxWidth) shortened = shortened.slice(0, -1);
  return `${shortened}…`;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge severity-${severity.toLowerCase()}`}>{severity}</span>;
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`badge status-${status.toLowerCase().replaceAll(" ", "-")}`}>
      <span className="status-dot" aria-hidden="true" />
      {status}
    </span>
  );
}

function MetricCard({
  label,
  value,
  detail,
  tone,
  trend,
}: {
  label: string;
  value: string;
  detail: string;
  tone: "critical" | "high" | "positive" | "neutral";
  trend?: string;
}) {
  return (
    <article className="metric-card">
      <div className="metric-topline">
        <span className={`metric-indicator ${tone}`} aria-hidden="true" />
        <span>{label}</span>
        {trend && <span className="metric-trend">{trend}</span>}
      </div>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

function EmptyState({ onReset }: { onReset: () => void }) {
  return (
    <div className="empty-state">
      <div className="empty-glyph">⌁</div>
      <h3>No paths match these filters</h3>
      <p>Try a different severity, account, or search term.</p>
      <button className="button secondary" onClick={onReset}>Clear filters</button>
    </div>
  );
}

export type DashboardUser = {
  displayName: string;
  email: string;
  role: "admin" | "operator" | "reviewer" | "viewer";
  localDevelopment: boolean;
};

export default function CloudPenDashboard({
  currentUser,
  initialExposure,
}: {
  currentUser: DashboardUser;
  initialExposure: { accounts: CloudAccount[]; assets: CloudAsset[]; attackPaths: AttackPath[] };
}) {
  const { accounts, assets, attackPaths } = initialExposure;
  const [view, setView] = useState<ViewKey>("overview");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"All" | Severity>("All");
  const [account, setAccount] = useState("All accounts");
  const [selectedPath, setSelectedPath] = useState<AttackPath>(attackPaths[0]);
  const [pathSort, setPathSort] = useState<"risk" | "recent">("risk");
  const [runFilter, setRunFilter] = useState<"all" | "approvals">("all");
  const [runs, setRuns] = useState<ValidationRun[]>([]);
  const [connectors, setConnectors] = useState<ConnectorRecord[]>([]);
  const [evidencePackages, setEvidencePackages] = useState<EvidenceRecord[]>([]);
  const [remediations, setRemediations] = useState<RemediationRecord[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditRecord[]>([]);
  const [runners, setRunners] = useState<RunnerRecord[]>([]);
  const [screenshots, setScreenshots] = useState<ScreenshotEvidenceRecord[]>([]);
  const [screenshotsLoading, setScreenshotsLoading] = useState(true);
  const [screenshotFilters, setScreenshotFilters] = useState({ frameworkId: "", controlId: "", query: "" });
  const [captureForm, setCaptureForm] = useState({
    frameworkId: complianceFrameworks[0].id,
    controlId: complianceFrameworks[0].controls[0].id,
    title: "",
    customName: "control-evidence",
    notes: "",
    bannerPosition: "bottom" as "top" | "bottom",
    includeTimestamp: true,
    includeActor: true,
    downloadCopy: true,
    authorized: false,
  });
  const [captureState, setCaptureState] = useState<"idle" | "choosing" | "uploading">("idle");
  const [captureError, setCaptureError] = useState("");
  const [auditChainValid, setAuditChainValid] = useState(true);
  const [dataMode, setDataMode] = useState<"demo" | "live">("demo");
  const [loadingControlPlane, setLoadingControlPlane] = useState(true);
  const [modal, setModal] = useState<"validate" | "connect" | "remediate" | "run" | "capture" | null>(null);
  const [selectedRun, setSelectedRun] = useState<ValidationRun | null>(null);
  const [decisionReason, setDecisionReason] = useState("");
  const [validationMode, setValidationMode] = useState<"Read-only" | "Active canary">("Read-only");
  const [runPathId, setRunPathId] = useState(attackPaths[0].id);
  const [acknowledged, setAcknowledged] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [accountForm, setAccountForm] = useState({ name: "", id: "", externalId: "" });
  const [accountError, setAccountError] = useState("");
  const [remediationForm, setRemediationForm] = useState({ owner: "", dueAt: "" });
  const [remediationError, setRemediationError] = useState("");
  const [runnerForm, setRunnerForm] = useState({ name: "", fingerprint: "" });
  const [runnerError, setRunnerError] = useState("");
  const [guardrails, setGuardrails] = useState({
    requireApproval: true,
    canaryOnly: true,
    redactEvidence: true,
    cleanupRequired: true,
  });
  const canPlan = currentUser.role === "admin" || currentUser.role === "operator";
  const canConfigure = currentUser.role === "admin";
  const canConnect = currentUser.role === "admin" || currentUser.role === "operator";
  const canApprove = currentUser.role === "admin" || currentUser.role === "reviewer";
  const canCapture = currentUser.role !== "viewer";

  useEffect(() => {
    let cancelled = false;
    fetch("/api/control-plane", { headers: { accept: "application/json" } })
      .then(async (response) => {
        if (!response.ok) throw new Error("Run history is temporarily unavailable.");
        return response.json() as Promise<ControlPlaneSnapshot>;
      })
      .then((snapshot) => {
        if (!cancelled) {
          setRuns(snapshot.runs);
          setConnectors(snapshot.connectors);
          setEvidencePackages(snapshot.evidence);
          setRemediations(snapshot.remediations);
          setAuditEvents(snapshot.audit);
          setRunners(snapshot.runners);
          setAuditChainValid(snapshot.auditChainValid);
          setDataMode(snapshot.workspace.dataMode);
          setLoadingControlPlane(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setLoadingControlPlane(false);
          setToast("Authoritative workspace data is unavailable. No cached security records are being shown.");
        }
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    void searchScreenshots({ frameworkId: "", controlId: "", query: "" });
  }, []);

  useEffect(() => {
    const restoreView = () => {
      const candidate = new URL(window.location.href).searchParams.get("view") as ViewKey | null;
      if (candidate && navigation.some((item) => item.key === candidate)) setView(candidate);
    };
    restoreView();
    window.addEventListener("popstate", restoreView);
    return () => window.removeEventListener("popstate", restoreView);
  }, []);

  async function refreshControlPlane() {
    const response = await fetch("/api/control-plane", { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error("Workspace records could not be refreshed.");
    const snapshot = await response.json() as ControlPlaneSnapshot;
    setRuns(snapshot.runs);
    setConnectors(snapshot.connectors);
    setEvidencePackages(snapshot.evidence);
    setRemediations(snapshot.remediations);
    setAuditEvents(snapshot.audit);
    setRunners(snapshot.runners);
    setAuditChainValid(snapshot.auditChainValid);
    setDataMode(snapshot.workspace.dataMode);
  }

  useEffect(() => {
    let cancelled = false;
    fetch("/api/guardrails", { headers: { accept: "application/json" } })
      .then(async (response) => {
        if (!response.ok) throw new Error("Guardrail policy is temporarily unavailable.");
        return response.json() as Promise<{ policy: typeof guardrails }>;
      })
      .then(({ policy }) => { if (!cancelled) setGuardrails(policy); })
      .catch(() => { if (!cancelled) setToast("Guardrail policy could not be loaded. Mutating operations remain fail-closed."); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const filteredPaths = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return attackPaths
      .filter((path) => severity === "All" || path.severity === severity)
      .filter((path) => account === "All accounts" || path.account === account)
      .filter(
        (path) =>
          !normalized ||
          [path.title, path.summary, path.target, path.id, path.account]
            .join(" ")
            .toLowerCase()
            .includes(normalized),
      )
      .sort((a, b) =>
        pathSort === "risk"
          ? severityRank[b.severity] - severityRank[a.severity] || b.score - a.score
          : attackPaths.indexOf(a) - attackPaths.indexOf(b),
      );
  }, [account, pathSort, query, severity]);

  const filteredAssets = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return assets.filter(
      (asset) =>
        (account === "All accounts" || asset.account === account) &&
        (!normalized ||
          [asset.name, asset.type, asset.owner, asset.account]
            .join(" ")
            .toLowerCase()
            .includes(normalized)),
    );
  }, [account, query]);

  function chooseView(next: ViewKey) {
    setView(next);
    setMobileNavOpen(false);
    const url = new URL(window.location.href);
    if (next === "overview") url.searchParams.delete("view"); else url.searchParams.set("view", next);
    window.history.pushState({}, "", `${url.pathname}${url.search}${url.hash}`);
  }

  function resetFilters() {
    setQuery("");
    setSeverity("All");
    setAccount("All accounts");
  }

  async function searchScreenshots(filters = screenshotFilters) {
    setScreenshotsLoading(true);
    try {
      const parameters = new URLSearchParams();
      if (filters.frameworkId) parameters.set("framework", filters.frameworkId);
      if (filters.controlId) parameters.set("control", filters.controlId);
      if (filters.query.trim()) parameters.set("q", filters.query.trim());
      const response = await fetch(`/api/screenshots?${parameters}`, { headers: { accept: "application/json" } });
      const body = await response.json() as { screenshots?: ScreenshotEvidenceRecord[]; error?: string };
      if (!response.ok || !body.screenshots) throw new Error(body.error || "Screenshot evidence could not be loaded.");
      setScreenshots(body.screenshots);
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Screenshot evidence could not be loaded.");
    } finally {
      setScreenshotsLoading(false);
    }
  }

  function openCapture() {
    setCaptureError("");
    setCaptureState("idle");
    setCaptureForm((current) => ({ ...current, authorized: false }));
    setModal("capture");
  }

  async function captureScreenshot(event: React.FormEvent) {
    event.preventDefault();
    const framework = frameworkById(captureForm.frameworkId);
    const control = framework?.controls.find((item) => item.id === captureForm.controlId);
    if (!framework || !control || captureForm.title.trim().length < 2 || !captureForm.customName.trim() || !captureForm.authorized) {
      setCaptureError("Choose a framework and control, add a title and filename, and confirm capture authorization.");
      return;
    }
    if (!navigator.mediaDevices?.getDisplayMedia) {
      setCaptureError("Screen capture is unavailable in this browser. Use a current browser on localhost or HTTPS.");
      return;
    }

    let stream: MediaStream | null = null;
    try {
      setCaptureError("");
      setCaptureState("choosing");
      stream = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
      const video = document.createElement("video");
      video.muted = true;
      video.playsInline = true;
      video.srcObject = stream;
      await new Promise<void>((resolve, reject) => {
        video.onloadedmetadata = () => resolve();
        video.onerror = () => reject(new Error("The selected screen could not be decoded."));
      });
      await video.play();
      const sourceWidth = video.videoWidth;
      const sourceHeight = video.videoHeight;
      if (!sourceWidth || !sourceHeight) throw new Error("The selected screen did not provide a usable frame.");

      const bannerHeight = Math.max(70, Math.min(104, Math.round(sourceWidth * 0.055)));
      const canvas = document.createElement("canvas");
      canvas.width = sourceWidth;
      canvas.height = sourceHeight + bannerHeight;
      const context = canvas.getContext("2d", { alpha: false });
      if (!context) throw new Error("The screenshot canvas could not be created.");
      context.fillStyle = "#07110d";
      context.fillRect(0, 0, canvas.width, canvas.height);
      const imageY = captureForm.bannerPosition === "top" ? bannerHeight : 0;
      const bannerY = captureForm.bannerPosition === "top" ? 0 : sourceHeight;
      context.drawImage(video, 0, imageY, sourceWidth, sourceHeight);
      const gradient = context.createLinearGradient(0, bannerY, sourceWidth, bannerY);
      gradient.addColorStop(0, "#08120e");
      gradient.addColorStop(1, "#10231b");
      context.fillStyle = gradient;
      context.fillRect(0, bannerY, sourceWidth, bannerHeight);
      context.fillStyle = "#62e6ad";
      context.fillRect(0, bannerY, 6, bannerHeight);

      const padding = Math.max(20, Math.round(sourceWidth * 0.018));
      const primarySize = Math.max(14, Math.min(24, Math.round(sourceWidth / 80)));
      const secondarySize = Math.max(11, Math.round(primarySize * 0.68));
      const leftWidth = sourceWidth * 0.62;
      context.textBaseline = "middle";
      context.fillStyle = "#f0f4f2";
      context.font = `700 ${primarySize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      context.fillText(fitCanvasText(context, `${framework.shortLabel} · ${control.id} · ${control.title}`, leftWidth), padding, bannerY + bannerHeight * 0.36);
      context.fillStyle = "#9db3a8";
      context.font = `500 ${secondarySize}px ui-monospace, SFMono-Regular, Menlo, monospace`;
      context.fillText(fitCanvasText(context, `${captureForm.title.trim()} · ${captureForm.customName.trim()}.png`, leftWidth), padding, bannerY + bannerHeight * 0.72);
      const capturedAt = new Date().toISOString();
      const rightLines = [
        captureForm.includeTimestamp ? capturedAt : "",
        captureForm.includeActor ? currentUser.email : "",
      ].filter(Boolean);
      context.textAlign = "right";
      context.fillStyle = "#b9cac1";
      rightLines.forEach((line, index) => context.fillText(fitCanvasText(context, line, sourceWidth * 0.3), sourceWidth - padding, bannerY + bannerHeight * (rightLines.length === 1 ? 0.53 : 0.36 + index * 0.36)));

      const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob((value) => value ? resolve(value) : reject(new Error("The PNG could not be encoded.")), "image/png"));
      setCaptureState("uploading");
      const form = new FormData();
      form.set("image", blob, "capture.png");
      form.set("frameworkId", framework.id);
      form.set("controlId", control.id);
      form.set("title", captureForm.title.trim());
      form.set("customName", captureForm.customName.trim());
      form.set("notes", captureForm.notes.trim());
      form.set("bannerPosition", captureForm.bannerPosition);
      form.set("includeTimestamp", String(captureForm.includeTimestamp));
      form.set("includeActor", String(captureForm.includeActor));
      form.set("capturedAt", capturedAt);
      form.set("authorized", "true");
      const response = await fetch("/api/screenshots", { method: "POST", body: form });
      const body = await response.json() as { screenshot?: ScreenshotEvidenceRecord; error?: string };
      if (!response.ok || !body.screenshot) throw new Error(body.error || "The screenshot could not be stored.");
      if (captureForm.downloadCopy) {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = body.screenshot.storedFilename;
        anchor.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setModal(null);
      setCaptureForm((current) => ({ ...current, title: "", notes: "", authorized: false }));
      setScreenshotFilters({ frameworkId: framework.id, controlId: control.id, query: "" });
      await searchScreenshots({ frameworkId: framework.id, controlId: control.id, query: "" });
      chooseView("screenshots");
      setToast(`Screenshot stored in ${body.screenshot.folderPath}.`);
    } catch (error) {
      const message = error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")
        ? "Capture was cancelled or screen-sharing permission was denied. No image was stored."
        : error instanceof Error ? error.message : "The screenshot could not be captured.";
      setCaptureError(message);
    } finally {
      stream?.getTracks().forEach((track) => track.stop());
      setCaptureState("idle");
    }
  }

  function openValidation(pathId = selectedPath.id) {
    setRunPathId(pathId);
    setValidationMode("Read-only");
    setAcknowledged(false);
    setModal("validate");
  }

  async function startValidation() {
    if (validationMode === "Active canary" && !acknowledged) return;
    try {
      const response = await fetch("/api/validation-runs", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ attackPathId: runPathId, mode: validationMode, acknowledged }),
      });
      const body = await response.json() as { run?: ValidationRun; error?: string };
      if (!response.ok || !body.run) throw new Error(body.error || "The validation plan could not be created.");
      setRuns((current) => [body.run!, ...current.filter((run) => run.id !== body.run!.id)]);
      await refreshControlPlane();
      setModal(null);
      setView("runs");
      setToast(body.run.status === "Awaiting approval"
        ? "Signed plan created. A separate reviewer must approve it before any runner can receive it."
        : "Signed read-only plan created. Cloud execution remains disabled in this release.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "The validation plan could not be created.");
    }
  }

  async function connectAccount(event: React.FormEvent) {
    event.preventDefault();
    if (!accountForm.name.trim()) {
      setAccountError("Enter a recognizable account name.");
      return;
    }
    if (!/^\d{12}$/.test(accountForm.id.replaceAll("-", ""))) {
      setAccountError("AWS account ID must contain exactly 12 digits.");
      return;
    }
    if (accountForm.externalId.trim().length < 8) {
      setAccountError("External ID must be at least 8 characters.");
      return;
    }
    try {
      const response = await fetch("/api/connectors", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          name: accountForm.name.trim(),
          accountId: accountForm.id.replaceAll("-", ""),
          externalId: accountForm.externalId.trim(),
        }),
      });
      const body = await response.json() as { error?: string };
      if (!response.ok) throw new Error(body.error || "The connector request could not be saved.");
      await refreshControlPlane();
      setAccountError("");
      setModal(null);
      setView("connectors");
      setToast("Connector request recorded. No AWS trust or credentials were created; runner provisioning is still required.");
      setAccountForm({ name: "", id: "", externalId: "" });
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : "The connector request could not be saved.");
    }
  }

  async function exportEvidence(path: AttackPath) {
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(path.id)}`, { headers: { accept: "application/json" } });
      if (!response.ok) {
        const body = await response.json() as { error?: string };
        throw new Error(body.error || "Evidence export failed.");
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = href;
      link.download = `${path.id.toLowerCase()}-evidence.json`;
      link.click();
      URL.revokeObjectURL(href);
      await refreshControlPlane();
      setToast("Server-signed evidence package exported with sensitive values redacted.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Evidence export failed.");
    }
  }

  function openRemediation(path = selectedPath) {
    setSelectedPath(path);
    const due = new Date(Date.now() + 14 * 24 * 60 * 60_000).toISOString().slice(0, 10);
    setRemediationForm({ owner: path.account, dueAt: due });
    setRemediationError("");
    setModal("remediate");
  }

  async function createRemediationDraft() {
    try {
      const response = await fetch("/api/remediations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ pathId: selectedPath.id, ...remediationForm }),
      });
      const body = await response.json() as { remediation?: RemediationRecord; error?: string };
      if (!response.ok || !body.remediation) throw new Error(body.error || "The remediation could not be created.");
      await refreshControlPlane();
      setModal(null);
      setView("remediation");
      setToast("Remediation created with an accountable owner and due date.");
    } catch (error) {
      setRemediationError(error instanceof Error ? error.message : "The remediation could not be created.");
    }
  }

  async function decideRun(run: ValidationRun, decision: "approve" | "reject" | "cancel") {
    try {
      const response = await fetch(`/api/validation-runs/${encodeURIComponent(run.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision, reason: decisionReason }),
      });
      const body = await response.json() as { error?: string };
      if (!response.ok) throw new Error(body.error || "The plan decision could not be recorded.");
      await refreshControlPlane();
      setModal(null);
      setDecisionReason("");
      setToast(`Plan ${decision === "approve" ? "approved" : decision === "reject" ? "rejected" : "cancelled"}. It remains non-executable.`);
    } catch (error) {
      setToast(error instanceof Error ? error.message : "The plan decision could not be recorded.");
    }
  }

  async function updateRemediationStatus(record: RemediationRecord, status: RemediationRecord["status"]) {
    try {
      const response = await fetch(`/api/remediations/${encodeURIComponent(record.id)}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status }),
      });
      const body = await response.json() as { error?: string };
      if (!response.ok) throw new Error(body.error || "Remediation status could not be updated.");
      await refreshControlPlane();
      setToast("Remediation status updated and audited.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Remediation status could not be updated.");
    }
  }

  async function planDiscovery(connector: ConnectorRecord) {
    try {
      const response = await fetch(`/api/connectors/${encodeURIComponent(connector.id)}/discovery`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const body = await response.json() as { error?: string };
      if (!response.ok) throw new Error(body.error || "Discovery plan could not be created.");
      await refreshControlPlane();
      setToast("A non-executable read-only discovery plan was recorded. Runner enrollment is still required.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Discovery plan could not be created.");
    }
  }

  async function exportGuardrails() {
    const response = await fetch("/api/guardrails/export", { headers: { accept: "application/json" } });
    if (!response.ok) return setToast("Signed guardrail export could not be created.");
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = "cloudpen-guardrails.json";
    link.click();
    URL.revokeObjectURL(href);
    setToast("Signed, non-executable guardrail policy exported.");
  }

  async function exportAssessment() {
    const response = await fetch("/api/reports/export", { headers: { accept: "application/json" } });
    if (!response.ok) return setToast("Assessment report could not be created.");
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = "cloudpen-assessment.json";
    link.click();
    URL.revokeObjectURL(href);
    await refreshControlPlane();
    setToast("Signed assessment report exported and audited.");
  }

  async function enrollRunner(event: React.FormEvent) {
    event.preventDefault();
    try {
      const response = await fetch("/api/runners", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: runnerForm.name, publicKeyFingerprint: runnerForm.fingerprint }),
      });
      const body = await response.json() as { error?: string };
      if (!response.ok) throw new Error(body.error || "Runner enrollment could not be staged.");
      await refreshControlPlane();
      setRunnerForm({ name: "", fingerprint: "" });
      setRunnerError("");
      setToast("Runner enrollment staged as pending and non-executable.");
    } catch (error) {
      setRunnerError(error instanceof Error ? error.message : "Runner enrollment could not be staged.");
    }
  }

  function renderOverview() {
    const validated = attackPaths.filter((path) => path.status === "Validated").length;
    const critical = attackPaths.filter((path) => path.severity === "Critical" && path.status !== "Mitigated").length;
    const coverage = Math.round((attackPaths.filter((path) => path.status !== "Inferred").length / attackPaths.length) * 100);
    return (
      <>
        <section className="metrics-grid" aria-label="Exposure metrics">
          <MetricCard label="Validated exposure" value={String(validated).padStart(2, "0")} detail="Server-catalog paths with retained proof" tone="critical" />
          <MetricCard label="Critical paths" value={String(critical).padStart(2, "0")} detail="Unmitigated paths with critical impact" tone="high" />
          <MetricCard label="Validation coverage" value={`${coverage}%`} detail={`${attackPaths.length} reachable paths in this ${dataMode} catalog`} tone="positive" />
          <MetricCard label="Open remediation" value={String(remediations.filter((item) => item.status !== "Closed").length).padStart(2, "0")} detail="Durable owner and SLA records" tone="neutral" />
        </section>

        <section className="overview-layout">
          <div className="panel priority-panel">
            <div className="panel-header">
              <div>
                <span className="section-kicker">ATTACK PATHS</span>
                <h2>Priority exposure</h2>
              </div>
              <button className="text-button" onClick={() => chooseView("paths")}>View all <span>→</span></button>
            </div>
            <div className="path-list compact">
              {attackPaths.slice(0, 3).map((path) => (
                <button
                  className="path-row"
                  key={path.id}
                  onClick={() => {
                    setSelectedPath(path);
                    chooseView("paths");
                  }}
                >
                  <div className={`risk-rail severity-${path.severity.toLowerCase()}`} aria-hidden="true" />
                  <div className="path-row-main">
                    <div className="path-row-meta">
                      <SeverityBadge severity={path.severity} />
                      <span>{path.id}</span>
                      <span>{path.steps.length} steps</span>
                    </div>
                    <h3>{path.title}</h3>
                    <p>{path.steps[0].label} <span>→</span> {path.target}</p>
                  </div>
                  <div className="path-row-side">
                    <strong>{path.score.toFixed(1)}</strong>
                    <span>Risk score</span>
                    <span className="row-arrow">›</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          <aside className="panel coverage-panel">
            <div className="panel-header">
              <div>
                <span className="section-kicker">30-DAY POSTURE</span>
                <h2>Validation coverage</h2>
              </div>
              <button className="icon-button subtle" aria-label="Coverage information" onClick={() => setToast("Coverage is the share of current snapshot paths with validated or mitigated evidence.")}>i</button>
            </div>
            <div className="coverage-visual">
              <div className="coverage-ring" style={{ background: `conic-gradient(var(--green) 0 ${coverage}%, #1b2530 ${coverage}% 100%)` }} aria-label={`${coverage} percent validation coverage`}>
                <div><strong>{coverage}%</strong><span>covered</span></div>
              </div>
              <div className="coverage-legend">
                <div><span className="legend-dot validated" /> <span>Validated</span><strong>{validated}</strong></div>
                <div><span className="legend-dot inferred" /> <span>Inferred only</span><strong>{attackPaths.filter((path) => path.status === "Inferred").length}</strong></div>
                <div><span className="legend-dot stale" /> <span>Mitigated</span><strong>{attackPaths.filter((path) => path.status === "Mitigated").length}</strong></div>
              </div>
            </div>
            <div className="coverage-note">
              <span className="note-icon">↗</span>
              <div><strong>Provenance is explicit</strong><p>These metrics are derived from the server-identified {dataMode} catalog.</p></div>
            </div>
          </aside>
        </section>

        <section className="panel activity-panel">
          <div className="panel-header">
            <div>
              <span className="section-kicker">RECENT ACTIVITY</span>
              <h2>Validation runs</h2>
            </div>
            <button className="text-button" onClick={() => chooseView("runs")}>Open run history <span>→</span></button>
          </div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>Run</th><th>Mode</th><th>Status</th><th>Paths</th><th>Findings</th><th>Started</th></tr></thead>
              <tbody>
                {!loadingControlPlane && runs.length === 0 && <tr><td colSpan={6}><strong>No durable validation plans yet</strong><span className="cell-subtext">Create a signed plan to begin an auditable workflow.</span></td></tr>}
                {runs.slice(0, 3).map((run) => (
                  <tr key={run.id}>
                    <td><strong>{run.name}</strong><span className="cell-subtext">{run.id} · {run.requestedBy}</span></td>
                    <td>{run.mode}</td>
                    <td><StatusBadge status={run.status} /></td>
                    <td>{run.pathCount}</td>
                    <td>{run.findings || "—"}</td>
                    <td>{run.started}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  }

  function renderPaths() {
    return (
      <section className="path-workspace">
        <div className="panel path-browser">
          <div className="path-toolbar">
            <label className="filter-search">
              <span>⌕</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search paths, targets, IDs…" aria-label="Search attack paths" />
            </label>
            <select value={severity} onChange={(event) => setSeverity(event.target.value as "All" | Severity)} aria-label="Filter by severity">
              <option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
            </select>
            <select value={pathSort} onChange={(event) => setPathSort(event.target.value as "risk" | "recent")} aria-label="Sort attack paths">
              <option value="risk">Highest risk</option><option value="recent">Most recent</option>
            </select>
          </div>
          <div className="browser-summary"><strong>{filteredPaths.length}</strong> paths <span>·</span> {filteredPaths.filter((path) => path.status === "Validated").length} validated</div>
          {filteredPaths.length === 0 ? <EmptyState onReset={resetFilters} /> : (
            <div className="path-list">
              {filteredPaths.map((path) => (
                <button className={`path-row ${selectedPath.id === path.id ? "selected" : ""}`} key={path.id} onClick={() => setSelectedPath(path)}>
                  <div className={`risk-rail severity-${path.severity.toLowerCase()}`} aria-hidden="true" />
                  <div className="path-row-main">
                    <div className="path-row-meta"><SeverityBadge severity={path.severity} /><StatusBadge status={path.status} /><span>{path.id}</span></div>
                    <h3>{path.title}</h3>
                    <p>{path.account} · {path.region}</p>
                  </div>
                  <div className="path-row-side"><strong>{path.score.toFixed(1)}</strong><span>Risk</span></div>
                </button>
              ))}
            </div>
          )}
        </div>

        <article className="panel path-detail">
          <div className="detail-header">
            <div>
              <div className="detail-meta"><SeverityBadge severity={selectedPath.severity} /><StatusBadge status={selectedPath.status} /><span>{selectedPath.id}</span></div>
              <h2>{selectedPath.title}</h2>
              <p>{selectedPath.summary}</p>
            </div>
            <div className="detail-score"><strong>{selectedPath.score.toFixed(1)}</strong><span>Risk score</span></div>
          </div>
          <div className="detail-actions">
            <button className="button primary" disabled={!canPlan} title={!canPlan ? "Operator or administrator role required" : undefined} onClick={() => openValidation(selectedPath.id)}>▶ Validate path</button>
            <button className="button secondary" onClick={() => exportEvidence(selectedPath)}>⇩ Export evidence</button>
            <button className="button ghost" onClick={() => openRemediation()}>View remediation</button>
          </div>

          <div className="detail-section">
            <div className="section-heading"><span className="section-kicker">OBSERVED CHAIN</span><span>{selectedPath.steps.length} steps · {selectedPath.updated}</span></div>
            <div className="attack-chain">
              {selectedPath.steps.map((step, index) => (
                <div className="chain-fragment" key={`${step.label}-${index}`}>
                  <div className={`chain-node ${step.type}`}>
                    <span className="node-index">0{index + 1}</span>
                    <span className="node-icon">{step.type === "identity" ? "ID" : step.type === "permission" ? "IAM" : step.type === "service" ? "AWS" : "DATA"}</span>
                    <strong>{step.label}</strong>
                    <small>{step.detail}</small>
                  </div>
                  {index < selectedPath.steps.length - 1 && <div className="chain-edge"><span>→</span></div>}
                </div>
              ))}
            </div>
          </div>

          <div className="evidence-grid">
            <section className="detail-section evidence-card">
              <div className="section-heading"><span className="section-kicker">VALIDATION EVIDENCE</span><StatusBadge status={selectedPath.status} /></div>
              <ul className="evidence-list">
                {selectedPath.evidence.map((item) => <li key={item}><span>✓</span><p>{item}</p></li>)}
              </ul>
            </section>
            <section className="detail-section cause-card">
              <span className="section-kicker">ROOT CAUSE</span>
              <p>{selectedPath.rootCause}</p>
              <button className="text-button" onClick={() => openRemediation()}>Open fix guidance <span>→</span></button>
            </section>
          </div>
        </article>
      </section>
    );
  }

  function renderAssets() {
    return (
      <section className="panel resource-panel">
        <div className="resource-toolbar">
          <label className="filter-search wide"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search assets, owners, or services…" aria-label="Search assets" /></label>
          <button className="button secondary" disabled title="Runner provisioning is required before inventory synchronization">↻ Sync inventory</button>
        </div>
        <div className="asset-stats">
          <div><span>Catalog assets</span><strong>{assets.length}</strong></div>
          <div><span>IAM roles</span><strong>{assets.filter((asset) => asset.type === "IAM role").length}</strong></div>
          <div><span>Internet exposed</span><strong>{assets.filter((asset) => asset.exposure === "Internet").length}</strong></div>
          <div><span>Cross-account</span><strong>{assets.filter((asset) => asset.exposure === "Cross-account").length}</strong></div>
        </div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Resource</th><th>Type</th><th>Account</th><th>Exposure</th><th>Paths</th><th>Owner</th></tr></thead>
            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td><strong>{asset.name}</strong><span className="cell-subtext">{asset.id} · {asset.region}</span></td>
                  <td>{asset.type}</td>
                  <td>{asset.account}</td>
                  <td><StatusBadge status={asset.exposure} /></td>
                  <td><button className="table-link" onClick={() => { const match = attackPaths.find((path) => path.target === asset.name); if (match) setSelectedPath(match); chooseView("paths"); }}>{asset.paths}</button></td>
                  <td>{asset.owner}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filteredAssets.length === 0 && <EmptyState onReset={resetFilters} />}
      </section>
    );
  }

  function renderRuns() {
    const visibleRuns = runFilter === "approvals" ? runs.filter((run) => run.status === "Awaiting approval") : runs;
    return (
      <section className="panel resource-panel">
        <div className="resource-toolbar">
          <div className="segmented" aria-label="Run status filter"><button className={runFilter === "all" ? "active" : ""} onClick={() => setRunFilter("all")}>All runs</button><button className={runFilter === "approvals" ? "active" : ""} onClick={() => setRunFilter("approvals")}>Needs approval ({runs.filter((run) => run.status === "Awaiting approval").length})</button></div>
          <button className="button primary" disabled={!canPlan} title={!canPlan ? "Operator or administrator role required" : undefined} onClick={() => openValidation()}>＋ New validation</button>
        </div>
        <div className="run-timeline">
          {loadingControlPlane && <div className="empty-state"><h3>Loading authoritative run history…</h3></div>}
          {!loadingControlPlane && visibleRuns.length === 0 && <div className="empty-state"><div className="empty-glyph">◎</div><h3>{runFilter === "approvals" ? "No plans need approval" : "No validation plans yet"}</h3><p>{runFilter === "approvals" ? "New active-canary requests will appear here." : "Create a signed plan to begin an auditable validation workflow."}</p></div>}
          {visibleRuns.map((run) => (
            <button className="run-card run-card-button" key={run.id} onClick={() => { setSelectedRun(run); setDecisionReason(""); setModal("run"); }}>
              <div className={`run-marker status-${run.status.toLowerCase()}`} aria-hidden="true">{run.status === "Completed" ? "✓" : run.status === "Running" ? "··" : "×"}</div>
              <div className="run-content">
                <div className="run-title"><div><span>{run.id}</span><h3>{run.name}</h3></div><StatusBadge status={run.status} /></div>
                <div className="run-details"><span><small>MODE</small>{run.mode}</span><span><small>REQUESTED BY</small>{run.requestedBy}</span><span><small>STARTED</small>{run.started}</span><span><small>DURATION</small>{run.duration}</span><span><small>RESULT</small>{run.findings ? `${run.findings} finding${run.findings > 1 ? "s" : ""}` : "No exposure"}</span></div>
                {run.status === "Running" && <div className="run-progress"><span /><p>Runner state is read-only in this control-plane release.</p><em>Emergency stop unavailable</em></div>}
              </div>
            </button>
          ))}
        </div>
      </section>
    );
  }

  function renderConnectors() {
    return (
      <section className="panel resource-panel">
        <div className="resource-toolbar"><div><strong>Customer-controlled AWS roles</strong><span className="cell-subtext">No static access keys are stored</span></div><button className="button primary" disabled={!canConnect} onClick={() => setModal("connect")}>＋ Connect AWS account</button></div>
        {connectors.length === 0 ? <div className="empty-state"><div className="empty-glyph">⛓</div><h3>No durable connectors yet</h3><p>Create a credential-free connector request. Discovery remains disabled until a customer-hosted runner is enrolled.</p><button className="button primary" disabled={!canConnect} onClick={() => setModal("connect")}>Connect account</button></div> : (
          <div className="record-grid">{connectors.map((connector) => <article className="record-card" key={connector.id}><div className="record-card-top"><div><span className="section-kicker">{connector.provider} · {connector.id}</span><h3>{connector.name}</h3></div><StatusBadge status={connector.status} /></div><dl><div><dt>Account</dt><dd>{connector.accountId}</dd></div><div><dt>External ID</dt><dd>{connector.externalIdHint}</dd></div><div><dt>Created by</dt><dd>{connector.createdBy}</dd></div><div><dt>Last sync</dt><dd>{connector.lastSyncAt || "Never"}</dd></div></dl><button className="button secondary full" disabled={!canConnect || connector.status === "Disabled"} onClick={() => planDiscovery(connector)}>Plan read-only discovery</button></article>)}</div>
        )}
      </section>
    );
  }

  function renderRemediation() {
    return (
      <section className="panel resource-panel">
        <div className="resource-toolbar"><div><strong>Accountable exposure reduction</strong><span className="cell-subtext">Every change is appended to the workspace audit chain</span></div><button className="button primary" disabled={!canPlan} onClick={() => openRemediation()}>＋ New remediation</button></div>
        {remediations.length === 0 ? <div className="empty-state"><div className="empty-glyph">✓</div><h3>No remediations are being tracked</h3><p>Create one from a path to assign ownership, due date, and revalidation state.</p></div> : <div className="record-grid">{remediations.map((record) => <article className="record-card" key={record.id}><div className="record-card-top"><div><span className="section-kicker">{record.pathId} · {record.id}</span><h3>{record.title}</h3></div><SeverityBadge severity={record.priority} /></div><p>{record.guidance}</p><dl><div><dt>Owner</dt><dd>{record.owner}</dd></div><div><dt>Due</dt><dd>{new Date(record.dueAt).toLocaleDateString()}</dd></div><div><dt>Status</dt><dd>{record.status}</dd></div></dl><label className="field compact"><span>Workflow status</span><select value={record.status} disabled={!canPlan} onChange={(event) => updateRemediationStatus(record, event.target.value as RemediationRecord["status"])}><option>Open</option><option>In progress</option><option>Risk accepted</option><option>Ready to revalidate</option><option>Closed</option></select></label></article>)}</div>}
      </section>
    );
  }

  function renderEvidence() {
    return (
      <section className="assurance-layout">
        <div className="panel resource-panel"><div className="panel-header"><div><span className="section-kicker">SIGNED PACKAGES</span><h2>Evidence manifests</h2></div><StatusBadge status={auditChainValid ? "Verified" : "Attention"} /></div>{evidencePackages.length === 0 ? <div className="empty-state"><h3>No evidence packages exported</h3><p>Export evidence from an attack path to create a retained integrity manifest.</p></div> : <div className="table-scroll"><table><thead><tr><th>Package</th><th>Path</th><th>Digest</th><th>Created by</th><th>Created</th></tr></thead><tbody>{evidencePackages.map((record) => <tr key={record.id}><td><strong>{record.id}</strong><span className="cell-subtext">{record.keyId}</span></td><td>{record.pathId}</td><td><code>{record.digest.slice(0, 14)}…</code></td><td>{record.createdBy}</td><td>{new Date(record.createdAt).toLocaleString()}</td></tr>)}</tbody></table></div>}</div>
        <div className="panel resource-panel"><div className="panel-header"><div><span className="section-kicker">EVENT CHAIN</span><h2>Recent audit history</h2></div><StatusBadge status={auditChainValid ? "Verified" : "Attention"} /></div>{auditEvents.length === 0 ? <div className="empty-state"><h3>No audit events yet</h3></div> : <div className="audit-list">{auditEvents.slice(0, 30).map((event) => <article key={event.id}><span className="audit-marker" /><div><strong>{event.action}</strong><p>{event.actorEmail} · {event.target}</p><code>{event.eventHash.slice(0, 18)}…</code></div><time>{new Date(event.createdAt).toLocaleString()}</time></article>)}</div>}</div>
      </section>
    );
  }

  function renderScreenshots() {
    const selectedFilterFramework = frameworkById(screenshotFilters.frameworkId);
    return (
      <section className="screenshot-layout">
        <article className="panel capture-hero">
          <div><span className="section-kicker">CONTROL-MAPPED CAPTURE</span><h2>Turn a screen state into audit-ready evidence</h2><p>Choose the framework and control before capture. CloudPen adds a visible banner, creates a normalized filename, and stores the PNG privately under the matching framework and control folder.</p></div>
          <div className="capture-example"><span>FOLDER PATTERN</span><code>hipaa/164.312-a-1/2026/08/</code><span>FILE PATTERN</span><code>HIPAA_164.312-a-1_20260811T143000Z_access-review.png</code></div>
          <button className="button primary" disabled={!canCapture} title={!canCapture ? "Reviewer, operator, or administrator role required" : undefined} onClick={openCapture}>▣ Capture screenshot</button>
        </article>

        <article className="panel screenshot-library">
          <div className="panel-header"><div><span className="section-kicker">PRIVATE EVIDENCE LIBRARY</span><h2>Find screenshots by control</h2></div><span className="result-count">{screenshotsLoading ? "Searching…" : `${screenshots.length} result${screenshots.length === 1 ? "" : "s"}`}</span></div>
          <form className="screenshot-search" onSubmit={(event) => { event.preventDefault(); void searchScreenshots(); }}>
            <label className="field compact"><span>Compliance area</span><select value={screenshotFilters.frameworkId} onChange={(event) => setScreenshotFilters({ frameworkId: event.target.value, controlId: "", query: screenshotFilters.query })}><option value="">All frameworks</option>{complianceFrameworks.map((framework) => <option value={framework.id} key={framework.id}>{framework.label} · {framework.version}</option>)}</select></label>
            <label className="field compact"><span>Control number</span><select value={screenshotFilters.controlId} disabled={!selectedFilterFramework} onChange={(event) => setScreenshotFilters({ ...screenshotFilters, controlId: event.target.value })}><option value="">All controls</option>{selectedFilterFramework?.controls.map((control) => <option value={control.id} key={control.id}>{control.id} · {control.title}</option>)}</select></label>
            <label className="field compact search-wide"><span>Filename, title, or notes</span><input type="search" maxLength={100} value={screenshotFilters.query} onChange={(event) => setScreenshotFilters({ ...screenshotFilters, query: event.target.value })} placeholder="Search evidence…" /></label>
            <div className="search-actions"><button className="button secondary" type="button" onClick={() => { const cleared = { frameworkId: "", controlId: "", query: "" }; setScreenshotFilters(cleared); void searchScreenshots(cleared); }}>Clear</button><button className="button primary" type="submit">Search</button></div>
          </form>

          {screenshotsLoading ? <div className="empty-state"><h3>Searching private evidence…</h3><p>Control metadata is queried without exposing object-store paths.</p></div> : screenshots.length === 0 ? <div className="empty-state"><div className="empty-glyph">▣</div><h3>No screenshots match this control</h3><p>Clear the filters or capture the first piece of evidence for this control.</p><button className="button primary" disabled={!canCapture} onClick={openCapture}>Capture evidence</button></div> : <div className="screenshot-grid">{screenshots.map((record) => <article className="screenshot-card" key={record.id}>
            <a className="screenshot-preview" href={record.contentUrl} target="_blank" rel="noreferrer" aria-label={`Open ${record.title}`}><img src={record.contentUrl} alt={`${record.frameworkLabel} ${record.controlId}: ${record.title}`} loading="lazy" /></a>
            <div className="screenshot-card-body"><div className="screenshot-card-top"><div><div className="screenshot-badges"><span className="badge status-private">Private · {record.frameworkId}</span><span className="badge status-planned">Collector submitted</span></div><h3>{record.title}</h3></div><code>{record.controlId}</code></div><p>{record.controlLabel}</p>{record.notes && <p className="screenshot-notes">{record.notes}</p>}<dl><div><dt>Captured</dt><dd>{new Date(record.capturedAt).toLocaleString()}</dd></div><div><dt>Image</dt><dd>{record.width}×{record.height} · {formatBytes(record.sizeBytes)}</dd></div></dl><div className="file-location"><span>STORAGE PATH</span><code>{record.folderPath}/{record.storedFilename}</code></div><div className="card-actions"><button className="button secondary" type="button" onClick={async () => { try { await navigator.clipboard.writeText(`${record.folderPath}/${record.storedFilename}`); setToast("Evidence path copied."); } catch { setToast("The evidence path could not be copied."); } }}>Copy path</button><a className="button primary" href={record.downloadUrl}>Download PNG</a></div></div>
          </article>)}</div>}
        </article>
      </section>
    );
  }

  function renderReports() {
    const openRemediations = remediations.filter((item) => item.status !== "Closed").length;
    return <section className="report-layout"><article className="panel report-hero"><span className="section-kicker">SIGNED ASSESSMENT</span><h2>Cloud exposure and remediation report</h2><p>A bounded, machine-readable report derived from the current server-owned exposure snapshot and durable control-plane records.</p><div className="report-metrics"><div><strong>{attackPaths.length}</strong><span>attack paths</span></div><div><strong>{attackPaths.filter((path) => path.status === "Validated").length}</strong><span>validated</span></div><div><strong>{openRemediations}</strong><span>open remediations</span></div><div><strong>{evidencePackages.length}</strong><span>evidence packages</span></div></div><button className="button primary" onClick={exportAssessment}>⇩ Export signed JSON report</button></article><aside className="panel report-contents"><span className="section-kicker">REPORT CONTENTS</span><ul><li>Executive exposure summary</li><li>Evidence-backed path register</li><li>MITRE ATT&CK technique references</li><li>Root-cause remediation guidance</li><li>Ownership and SLA state</li><li>Audit-chain integrity status</li><li>Explicit demo/live provenance</li></ul><div className="connection-note"><span>i</span><p>PDF rendering and external ticket delivery are not enabled; the JSON envelope is signed and auditable.</p></div></aside></section>;
  }

  function renderAdministration() {
    return <section className="settings-layout"><div className="panel settings-panel"><div className="panel-header"><div><span className="section-kicker">CUSTOMER-HOSTED RUNNERS</span><h2>Enrollment staging</h2></div><StatusBadge status="Non-executable" /></div><p className="settings-intro">Enrollment records pin a public-key fingerprint for architectural review. They cannot exchange credentials, poll plans, or execute modules.</p>{runners.length > 0 && <div className="record-grid">{runners.map((runner) => <article className="record-card" key={runner.id}><div className="record-card-top"><div><span className="section-kicker">{runner.id}</span><h3>{runner.name}</h3></div><StatusBadge status={runner.status} /></div><p>Fingerprint: <code>{runner.publicKeyFingerprint.slice(0, 24)}…</code></p><p>Executable: <strong>false</strong></p></article>)}</div>}<form className="admin-form" onSubmit={enrollRunner}><label className="field"><span>Runner name</span><input value={runnerForm.name} onChange={(event) => setRunnerForm({ ...runnerForm, name: event.target.value })} placeholder="Production security runner" disabled={!canConfigure} /></label><label className="field"><span>SHA-256 public-key fingerprint</span><input value={runnerForm.fingerprint} onChange={(event) => setRunnerForm({ ...runnerForm, fingerprint: event.target.value })} placeholder="64 hexadecimal characters" disabled={!canConfigure} /></label>{runnerError && <p className="form-error" role="alert">{runnerError}</p>}<button className="button primary" disabled={!canConfigure || runnerForm.name.trim().length < 2 || !/^(sha256:)?[A-Fa-f0-9]{64}$/.test(runnerForm.fingerprint.trim())}>Stage enrollment</button></form></div><aside className="panel policy-summary"><span className="section-kicker">CURRENT IDENTITY</span><div className="policy-shield">{initials(currentUser.displayName)}</div><h2>{currentUser.displayName}</h2><p>{currentUser.email}</p><dl><div><dt>Workspace</dt><dd>Northstar Labs</dd></div><div><dt>Role</dt><dd>{currentUser.role}</dd></div><div><dt>Data mode</dt><dd>{dataMode}</dd></div><div><dt>Runner execution</dt><dd>Disabled</dd></div></dl></aside></section>;
  }

  function renderGuardrails() {
    const toggle = async (key: keyof typeof guardrails) => {
      const previous = guardrails;
      const next = { ...guardrails, [key]: !guardrails[key] };
      setGuardrails(next);
      try {
        const response = await fetch("/api/guardrails", {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ [key]: next[key] }),
        });
        const body = await response.json() as { policy?: typeof guardrails; error?: string };
        if (!response.ok || !body.policy) throw new Error(body.error || "Guardrail update failed.");
        setGuardrails(body.policy);
        setToast("Guardrail policy updated and appended to the audit chain.");
      } catch (error) {
        setGuardrails(previous);
        setToast(error instanceof Error ? error.message : "Guardrail update failed.");
      }
    };
    return (
      <section className="settings-layout">
        <div className="panel settings-panel">
          <div className="panel-header"><div><span className="section-kicker">DEFAULT POLICY</span><h2>Production execution controls</h2></div><StatusBadge status="Enforced" /></div>
          <p className="settings-intro">These constraints are evaluated before a plan is signed. A future enrolled runner must independently enforce the same or stricter policy.</p>
          <div className="settings-list">
            {[
              ["requireApproval", "Require human approval", "An authorized operator must approve every active-canary plan."],
              ["canaryOnly", "Restrict data actions to canaries", "Block read or write operations against untagged customer data."],
              ["redactEvidence", "Redact evidence at the runner", "Remove tokens, secrets, payloads, and customer values before upload."],
              ["cleanupRequired", "Require verified cleanup", "Keep the run open until every temporary resource is confirmed removed."],
            ].map(([key, label, description]) => (
              <div className="setting-row" key={key}>
                <div><strong>{label}</strong><p>{description}</p></div>
                <button className={`switch ${guardrails[key as keyof typeof guardrails] ? "on" : ""}`} role="switch" aria-checked={guardrails[key as keyof typeof guardrails]} aria-label={label} disabled={!canConfigure} title={!canConfigure ? "Administrator role required" : undefined} onClick={() => toggle(key as keyof typeof guardrails)}><span /></button>
              </div>
            ))}
          </div>
        </div>
        <aside className="panel policy-summary">
          <span className="section-kicker">ENFORCEMENT SUMMARY</span>
          <div className="policy-shield">◈</div>
          <h2>Safe by construction</h2>
          <p>The AI layer cannot issue arbitrary AWS calls. Every operation must match a signed module and this workspace policy.</p>
          <dl><div><dt>Max session</dt><dd>15 minutes</dd></div><div><dt>Concurrency</dt><dd>2 actions</dd></div><div><dt>Allowed regions</dt><dd>3</dd></div><div><dt>Denied services</dt><dd>11</dd></div></dl>
          <button className="button secondary full" onClick={exportGuardrails}>Export signed policy</button>
        </aside>
      </section>
    );
  }

  const title = viewTitles[view];
  const selectedCaptureFramework = frameworkById(captureForm.frameworkId) ?? complianceFrameworks[0];
  const selectedCaptureControl = selectedCaptureFramework.controls.find((control) => control.id === captureForm.controlId) ?? selectedCaptureFramework.controls[0];
  const captureFilenamePreview = screenshotFilename({ frameworkId: selectedCaptureFramework.id, controlId: selectedCaptureControl.id, customName: captureForm.customName || "evidence", capturedAt: new Date().toISOString() });
  const captureFolderPreview = `${selectedCaptureFramework.id}/${controlFolderSegment(selectedCaptureControl.id)}/YYYY/MM`;

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`}>
        <div className="brand"><span className="brand-mark">C</span><span><strong>CloudPen</strong><small>VALIDATION PLATFORM</small></span></div>
        <button className="workspace-card" onClick={() => setToast("Northstar Labs is the only workspace authorized for this identity.")}>
          <span className="workspace-avatar">NS</span><span><strong>Northstar Labs</strong><small>Enterprise workspace</small></span><span>⌄</span>
        </button>
        <nav aria-label="Primary navigation">
          <span className="nav-label">WORKSPACE</span>
          {navigation.map((item) => <button key={item.key} className={view === item.key ? "active" : ""} onClick={() => chooseView(item.key)}><span className="nav-icon">{item.icon}</span>{item.label}{item.key === "paths" && <span className="nav-count">{attackPaths.length}</span>}</button>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="runner-health"><div><span className="pulse paused" /><strong>Runner disabled</strong></div><p>Fail-closed · provisioning required</p></div>
          <button onClick={() => window.location.assign("/help")}><span className="nav-icon">?</span> Help & documentation</button>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setMobileNavOpen((open) => !open)} aria-expanded={mobileNavOpen} aria-label="Toggle navigation">☰</button>
          <label className="global-search"><span>⌕</span><input value={query} onChange={(event) => setQuery(event.target.value)} onFocus={() => view === "overview" && setView("paths")} placeholder="Search paths, assets, identities…" aria-label="Global search" /><kbd>⌘ K</kbd></label>
          <div className="topbar-actions">
            <select value={account} onChange={(event) => setAccount(event.target.value)} aria-label="Select cloud account"><option>All accounts</option>{accounts.map((item) => <option key={item.id}>{item.name}</option>)}</select>
            <div className="popover-anchor">
              <button className="icon-button" aria-label="Notifications" onClick={() => setNoticeOpen((open) => !open)}>♢<span className="notification-dot" /></button>
              {noticeOpen && <div className="popover notification-popover"><span className="section-kicker">WORKSPACE ACTIVITY</span><strong>{runs.filter((run) => run.status === "Awaiting approval").length ? `${runs.filter((run) => run.status === "Awaiting approval").length} plan(s) need review` : "No approvals waiting"}</strong><p>{remediations.filter((item) => item.status !== "Closed").length} open remediation record(s) · audit chain {auditChainValid ? "verified" : "requires attention"}.</p><button onClick={() => { setNoticeOpen(false); chooseView(runs.some((run) => run.status === "Awaiting approval") ? "runs" : "remediation"); }}>Open activity</button></div>}
            </div>
            <div className="popover-anchor">
              <button className="avatar-button" aria-label="Open profile menu" onClick={() => setProfileOpen((open) => !open)}>{initials(currentUser.displayName)}</button>
              {profileOpen && <div className="popover profile-popover"><strong>{currentUser.displayName}</strong><span>{currentUser.role} · {currentUser.email}</span>{currentUser.localDevelopment && <span>Loopback development identity</span>}<a href="/signout-with-chatgpt?return_to=%2F">Sign out</a></div>}
            </div>
          </div>
        </header>

        <main>
          <div className={`data-mode-banner ${dataMode}`} role="status"><strong>{dataMode === "demo" ? "Demo data" : "Live workspace"}</strong><span>{dataMode === "demo" ? "Attack paths and inventory are seeded examples. Durable plans, approvals, evidence, connectors, remediation, and audit events are real local records." : "Metrics and findings are derived from the current workspace inventory."}</span></div>
          <div className="page-heading">
            <div><span className="page-eyebrow">{title.eyebrow}</span><h1>{title.title}</h1><p>{title.description}</p></div>
            {view === "screenshots" ? <div className="heading-actions"><button className="button primary" disabled={!canCapture} title={!canCapture ? "Reviewer, operator, or administrator role required" : undefined} onClick={openCapture}>▣ Capture screenshot</button></div> : <div className="heading-actions"><button className="button secondary" disabled={!canConnect} title={!canConnect ? "Operator or administrator role required" : undefined} onClick={() => setModal("connect")}>＋ Connect account</button><button className="button primary" disabled={!canPlan} title={!canPlan ? "Operator or administrator role required" : undefined} onClick={() => openValidation()}>▶ New validation</button></div>}
          </div>
          {view === "overview" && renderOverview()}
          {view === "paths" && renderPaths()}
          {view === "assets" && renderAssets()}
          {view === "runs" && renderRuns()}
          {view === "connectors" && renderConnectors()}
          {view === "remediation" && renderRemediation()}
          {view === "screenshots" && renderScreenshots()}
          {(view === "evidence" || view === "audit") && renderEvidence()}
          {view === "reports" && renderReports()}
          {view === "administration" && renderAdministration()}
          {view === "guardrails" && renderGuardrails()}
        </main>
      </div>

      <nav className="mobile-bottom-nav" aria-label="Mobile navigation">
        {navigation.slice(0, 4).map((item) => <button key={item.key} className={view === item.key ? "active" : ""} onClick={() => chooseView(item.key)}><span>{item.icon}</span>{item.label.split(" ")[0]}</button>)}
      </nav>

      {modal && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setModal(null); }}>
        <section className={`modal ${modal === "capture" ? "capture-modal" : ""}`} role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <button className="modal-close" aria-label="Close dialog" onClick={() => setModal(null)}>×</button>
          {modal === "capture" && <form onSubmit={captureScreenshot} noValidate>
            <span className="section-kicker">PRIVATE COMPLIANCE EVIDENCE</span><h2 id="modal-title">Capture a control screenshot</h2><p className="modal-intro">Your browser will ask which screen, window, or tab to share. CloudPen captures one frame, stamps it locally, stops sharing, and uploads only the resulting PNG.</p>
            <div className="capture-form-grid"><label className="field"><span>Compliance area</span><select autoFocus value={captureForm.frameworkId} onChange={(event) => { const framework = frameworkById(event.target.value) ?? complianceFrameworks[0]; setCaptureForm({ ...captureForm, frameworkId: framework.id, controlId: framework.controls[0].id }); }}>{complianceFrameworks.map((framework) => <option value={framework.id} key={framework.id}>{framework.label} · {framework.version}</option>)}</select></label><label className="field"><span>Control number</span><select value={captureForm.controlId} onChange={(event) => setCaptureForm({ ...captureForm, controlId: event.target.value })}>{selectedCaptureFramework.controls.map((control) => <option value={control.id} key={control.id}>{control.id} · {control.title}</option>)}</select></label></div>
            <label className="field"><span>Evidence title</span><input maxLength={120} value={captureForm.title} onChange={(event) => setCaptureForm({ ...captureForm, title: event.target.value })} placeholder="Quarterly privileged access review" /></label>
            <label className="field"><span>Custom file name</span><input maxLength={80} value={captureForm.customName} onChange={(event) => setCaptureForm({ ...captureForm, customName: event.target.value })} placeholder="access-review" /><small>CloudPen removes unsafe path characters and adds the framework, control, and UTC timestamp.</small></label>
            <div className="naming-preview"><span>PRIVATE FOLDER</span><code>{captureFolderPreview}/</code><span>GENERATED FILE</span><code>{captureFilenamePreview}</code></div>
            <label className="field"><span>Evidence notes <em>optional</em></span><textarea maxLength={500} rows={3} value={captureForm.notes} onChange={(event) => setCaptureForm({ ...captureForm, notes: event.target.value })} placeholder="What this screenshot demonstrates, review period, or collection context" /></label>
            <div className="capture-form-grid"><label className="field"><span>Banner position</span><select value={captureForm.bannerPosition} onChange={(event) => setCaptureForm({ ...captureForm, bannerPosition: event.target.value as "top" | "bottom" })}><option value="bottom">Bottom</option><option value="top">Top</option></select></label><fieldset className="capture-options"><legend>Banner details</legend><label><input type="checkbox" checked={captureForm.includeTimestamp} onChange={(event) => setCaptureForm({ ...captureForm, includeTimestamp: event.target.checked })} /> UTC timestamp</label><label><input type="checkbox" checked={captureForm.includeActor} onChange={(event) => setCaptureForm({ ...captureForm, includeActor: event.target.checked })} /> Collector identity</label></fieldset></div>
            <label className="acknowledge"><input type="checkbox" checked={captureForm.downloadCopy} onChange={(event) => setCaptureForm({ ...captureForm, downloadCopy: event.target.checked })} /><span>Download a local copy after private storage succeeds.</span></label>
            <label className="acknowledge authorization-check"><input type="checkbox" checked={captureForm.authorized} onChange={(event) => setCaptureForm({ ...captureForm, authorized: event.target.checked })} /><span>I confirm I am authorized to capture the selected screen and have reviewed it for secrets, personal data, and unrelated content.</span></label>
            {captureError && <p className="form-error" role="alert">{captureError}</p>}
            <div className="connection-note"><span>i</span><p>The control number is always visible in the banner. Browser and operating-system sharing indicators remain authoritative; CloudPen stops every media track after one frame.</p></div>
            <div className="modal-actions"><button type="button" className="button secondary" disabled={captureState !== "idle"} onClick={() => setModal(null)}>Cancel</button><button className="button primary" type="submit" disabled={captureState !== "idle" || !captureForm.authorized || captureForm.title.trim().length < 2 || !captureForm.customName.trim()}>{captureState === "choosing" ? "Choose a screen…" : captureState === "uploading" ? "Storing securely…" : "Choose screen and capture"}</button></div>
          </form>}
          {modal === "validate" && <>
            <span className="section-kicker">AUTHORIZED TEST PLAN</span><h2 id="modal-title">Create validation run</h2><p className="modal-intro">Review the scope and execution mode before the runner receives a signed plan.</p>
            <label className="field"><span>Attack path</span><select value={runPathId} onChange={(event) => setRunPathId(event.target.value)}>{attackPaths.map((path) => <option key={path.id} value={path.id}>{path.id} · {path.title}</option>)}</select></label>
            <fieldset className="mode-picker"><legend>Execution mode</legend><label className={validationMode === "Read-only" ? "selected" : ""}><input type="radio" name="mode" checked={validationMode === "Read-only"} onChange={() => { setValidationMode("Read-only"); setAcknowledged(false); }} /><span><strong>Read-only proof</strong><small>Evaluate and assume roles without mutating resources.</small></span><em>Recommended</em></label><label className={validationMode === "Active canary" ? "selected" : ""}><input type="radio" name="mode" checked={validationMode === "Active canary"} onChange={() => setValidationMode("Active canary")} /><span><strong>Active canary</strong><small>Exercise tagged canary resources and verify detection.</small></span><em>Approval required</em></label></fieldset>
            <div className="plan-summary"><span>Planned controls</span><ul><li>15-minute STS session</li><li>2-operation concurrency cap</li><li>Automatic cleanup and evidence redaction</li></ul></div>
            {validationMode === "Active canary" && <label className="acknowledge"><input type="checkbox" checked={acknowledged} onChange={(event) => setAcknowledged(event.target.checked)} /><span>I confirm this test is authorized and limited to tagged canary resources.</span></label>}
            <div className="modal-actions"><button className="button secondary" onClick={() => setModal(null)}>Cancel</button><button className="button primary" disabled={validationMode === "Active canary" && !acknowledged} onClick={startValidation}>Create signed plan</button></div>
          </>}
          {modal === "connect" && <form onSubmit={connectAccount} noValidate>
            <span className="section-kicker">AWS CONNECTOR</span><h2 id="modal-title">Connect a cloud account</h2><p className="modal-intro">CloudPen uses a customer-controlled role with a unique External ID. No static access keys are stored.</p>
            <label className="field"><span>Account name</span><input value={accountForm.name} onChange={(event) => setAccountForm({ ...accountForm, name: event.target.value })} placeholder="e.g. Payments Production" autoFocus /></label>
            <label className="field"><span>AWS account ID</span><input value={accountForm.id} onChange={(event) => setAccountForm({ ...accountForm, id: event.target.value })} placeholder="123456789012" inputMode="numeric" /></label>
            <label className="field"><span>External ID</span><input value={accountForm.externalId} onChange={(event) => setAccountForm({ ...accountForm, externalId: event.target.value })} placeholder="northstar-cloudpen-prod" /><small>Use a unique value that is not shared with another vendor.</small></label>
            {accountError && <p className="form-error" role="alert">{accountError}</p>}
            <div className="connection-note"><span>i</span><p>This records a durable connector and External ID digest. A non-executable discovery plan can be created next; no AWS trust is changed by CloudPen.</p></div>
            <div className="modal-actions"><button type="button" className="button secondary" onClick={() => setModal(null)}>Cancel</button><button className="button primary" type="submit">Create connector record</button></div>
          </form>}
          {modal === "remediate" && <>
            <span className="section-kicker">ROOT-CAUSE REMEDIATION</span><h2 id="modal-title">Restrict the risky permission</h2><p className="modal-intro">This recommendation closes the shortest validated route while preserving the approved deployment workflow.</p>
            <div className="remediation-block"><span>WHY THIS FIX</span><p>{selectedPath.remediation}</p></div>
            <pre className="policy-code"><code>{selectedPath.id === "CP-1042" ? `{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": [
    "arn:aws:iam::410788211034:role/billing-worker"
  ],
  "Condition": {
    "StringEquals": {
      "iam:PassedToService": "lambda.amazonaws.com"
    }
  }
}` : JSON.stringify({ pathId: selectedPath.id, target: selectedPath.target, recommendation: selectedPath.remediation }, null, 2)}</code></pre>
            <label className="field"><span>Accountable owner</span><input value={remediationForm.owner} onChange={(event) => setRemediationForm({ ...remediationForm, owner: event.target.value })} placeholder="Team or person" /></label>
            <label className="field"><span>Due date</span><input type="date" value={remediationForm.dueAt} onChange={(event) => setRemediationForm({ ...remediationForm, dueAt: event.target.value })} /></label>
            {remediationError && <p className="form-error" role="alert">{remediationError}</p>}
            <div className="modal-actions"><button className="button secondary" onClick={() => setModal(null)}>Close</button><button className="button primary" disabled={!canPlan || remediationForm.owner.trim().length < 2 || !remediationForm.dueAt} onClick={createRemediationDraft}>Create tracked remediation</button></div>
          </>}
          {modal === "run" && selectedRun && <>
            <span className="section-kicker">SIGNED VALIDATION PLAN</span><h2 id="modal-title">{selectedRun.name}</h2><div className="receipt-grid"><div><span>Status</span><strong>{selectedRun.status}</strong></div><div><span>Mode</span><strong>{selectedRun.mode}</strong></div><div><span>Requester</span><strong>{selectedRun.requestedBy}</strong></div><div><span>Expires</span><strong>{selectedRun.expiresAt ? new Date(selectedRun.expiresAt).toLocaleString() : "Unavailable"}</strong></div></div><div className="receipt-block"><span>AUTHORIZATION DIGEST</span><code>{selectedRun.authorizationDigest || "Unavailable"}</code><span>SIGNATURE · HMAC-SHA-256 · cloudpen-plan-v1</span><code>{selectedRun.signature || "Unavailable"}</code><p>Execution flag: <strong>false</strong>. Approval records intent but cannot make this plan executable.</p></div>
            {selectedRun.decisionReason && <div className="remediation-block"><span>DECISION REASON</span><p>{selectedRun.decisionReason}</p></div>}
            {(selectedRun.status === "Awaiting approval" || selectedRun.status === "Planned" || selectedRun.status === "Approved") && <label className="field"><span>Decision reason</span><input value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)} placeholder="Record why this action is authorized" /></label>}
            <div className="modal-actions"><button className="button secondary" onClick={() => setModal(null)}>Close</button>{selectedRun.status === "Awaiting approval" && canApprove && <><button className="button secondary" disabled={decisionReason.trim().length < 4} onClick={() => decideRun(selectedRun, "reject")}>Reject</button><button className="button primary" disabled={decisionReason.trim().length < 4} onClick={() => decideRun(selectedRun, "approve")}>Approve intent</button></>}{(selectedRun.status === "Planned" || selectedRun.status === "Awaiting approval" || selectedRun.status === "Approved") && canPlan && <button className="button ghost" disabled={decisionReason.trim().length < 4} onClick={() => decideRun(selectedRun, "cancel")}>Cancel plan</button>}</div>
          </>}
        </section>
      </div>}

      {toast && <div className="toast" role="status"><span>✓</span>{toast}</div>}
    </div>
  );
}
