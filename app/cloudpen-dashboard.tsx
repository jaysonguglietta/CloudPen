"use client";

import { useEffect, useMemo, useState } from "react";
import {
  accounts,
  assets,
  attackPaths,
  initialRuns,
  severityRank,
  type AttackPath,
  type Severity,
  type ValidationRun,
  type ViewKey,
} from "../lib/cloudpen-data";

const navigation: Array<{ key: ViewKey; label: string; icon: string }> = [
  { key: "overview", label: "Exposure overview", icon: "⌂" },
  { key: "paths", label: "Attack paths", icon: "↗" },
  { key: "assets", label: "Assets & identities", icon: "◇" },
  { key: "runs", label: "Validation runs", icon: "▶" },
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
  guardrails: {
    eyebrow: "Safety policy",
    title: "Execution guardrails",
    description: "Constrain every validation before a credential or cloud API operation is allowed.",
  },
};

function initials(value: string): string {
  return value.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "CP";
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

export default function CloudPenDashboard({ currentUser }: { currentUser: DashboardUser }) {
  const [view, setView] = useState<ViewKey>("overview");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"All" | Severity>("All");
  const [account, setAccount] = useState("All accounts");
  const [selectedPath, setSelectedPath] = useState<AttackPath>(attackPaths[0]);
  const [pathSort, setPathSort] = useState<"risk" | "recent">("risk");
  const [runs, setRuns] = useState<ValidationRun[]>(initialRuns);
  const [modal, setModal] = useState<"validate" | "connect" | "remediate" | null>(null);
  const [validationMode, setValidationMode] = useState<"Read-only" | "Active canary">("Read-only");
  const [runPathId, setRunPathId] = useState(attackPaths[0].id);
  const [acknowledged, setAcknowledged] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [accountForm, setAccountForm] = useState({ name: "", id: "", externalId: "" });
  const [accountError, setAccountError] = useState("");
  const [guardrails, setGuardrails] = useState({
    requireApproval: true,
    canaryOnly: true,
    redactEvidence: true,
    cleanupRequired: true,
  });
  const canPlan = currentUser.role === "admin" || currentUser.role === "operator";
  const canConfigure = currentUser.role === "admin";
  const canConnect = currentUser.role === "admin" || currentUser.role === "operator";

  useEffect(() => {
    let cancelled = false;
    fetch("/api/validation-runs", { headers: { accept: "application/json" } })
      .then(async (response) => {
        if (!response.ok) throw new Error("Run history is temporarily unavailable.");
        return response.json() as Promise<{ runs: ValidationRun[] }>;
      })
      .then(({ runs: authoritativeRuns }) => {
        if (!cancelled && authoritativeRuns.length > 0) setRuns(authoritativeRuns);
      })
      .catch(() => {
        if (!cancelled) setToast("Authoritative run history is unavailable; showing labeled sample data.");
      });
    return () => { cancelled = true; };
  }, []);

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
  }

  function resetFilters() {
    setQuery("");
    setSeverity("All");
    setAccount("All accounts");
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
      setAccountError("");
      setModal(null);
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
      setToast("Server-signed evidence package exported with sensitive values redacted.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "Evidence export failed.");
    }
  }

  function renderOverview() {
    return (
      <>
        <section className="metrics-grid" aria-label="Exposure metrics">
          <MetricCard label="Validated exposure" value="06" detail="2 paths require action this week" tone="critical" trend="−2 this month" />
          <MetricCard label="Critical paths" value="01" detail="Reaches restricted customer data" tone="high" />
          <MetricCard label="Validation coverage" value="84%" detail="41 of 49 reachable paths tested" tone="positive" trend="+12%" />
          <MetricCard label="Mean time to close" value="4.2d" detail="Across the last 30 days" tone="neutral" trend="−1.1d" />
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
              <button className="icon-button subtle" aria-label="Coverage information" onClick={() => setToast("Coverage measures reachable paths tested in the last 30 days.")}>i</button>
            </div>
            <div className="coverage-visual">
              <div className="coverage-ring" aria-label="84 percent validation coverage">
                <div><strong>84%</strong><span>covered</span></div>
              </div>
              <div className="coverage-legend">
                <div><span className="legend-dot validated" /> <span>Validated</span><strong>41</strong></div>
                <div><span className="legend-dot inferred" /> <span>Inferred only</span><strong>8</strong></div>
                <div><span className="legend-dot stale" /> <span>Stale</span><strong>3</strong></div>
              </div>
            </div>
            <div className="coverage-note">
              <span className="note-icon">↗</span>
              <div><strong>Coverage improved 12%</strong><p>Eight IAM paths were revalidated after the July policy rollout.</p></div>
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
            <button className="button ghost" onClick={() => setModal("remediate")}>View remediation</button>
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
              <button className="text-button" onClick={() => setModal("remediate")}>Open fix guidance <span>→</span></button>
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
          <div><span>Inventoried assets</span><strong>3,035</strong></div>
          <div><span>Human identities</span><strong>186</strong></div>
          <div><span>Workload identities</span><strong>428</strong></div>
          <div><span>Cross-account trusts</span><strong>37</strong></div>
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
    return (
      <section className="panel resource-panel">
        <div className="resource-toolbar">
          <div className="segmented" aria-label="Run status filter"><button className="active">All runs</button><button onClick={() => setToast("No approvals are waiting for your action.")}>Needs approval</button></div>
          <button className="button primary" disabled={!canPlan} title={!canPlan ? "Operator or administrator role required" : undefined} onClick={() => openValidation()}>＋ New validation</button>
        </div>
        <div className="run-timeline">
          {runs.map((run) => (
            <article className="run-card" key={run.id}>
              <div className={`run-marker status-${run.status.toLowerCase()}`} aria-hidden="true">{run.status === "Completed" ? "✓" : run.status === "Running" ? "··" : "×"}</div>
              <div className="run-content">
                <div className="run-title"><div><span>{run.id}</span><h3>{run.name}</h3></div><StatusBadge status={run.status} /></div>
                <div className="run-details"><span><small>MODE</small>{run.mode}</span><span><small>REQUESTED BY</small>{run.requestedBy}</span><span><small>STARTED</small>{run.started}</span><span><small>DURATION</small>{run.duration}</span><span><small>RESULT</small>{run.findings ? `${run.findings} finding${run.findings > 1 ? "s" : ""}` : "No exposure"}</span></div>
                {run.status === "Running" && <div className="run-progress"><span /><p>Runner state is read-only in this control-plane release.</p><button disabled title="Server-owned emergency stop is not available until runner enrollment">Emergency stop unavailable</button></div>}
              </div>
            </article>
          ))}
        </div>
      </section>
    );
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
          <p className="settings-intro">These constraints are evaluated before a test plan is signed and again inside the customer-hosted runner.</p>
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
          <button className="button secondary full" disabled title="Signed policy export will be enabled with runner enrollment">Export policy unavailable</button>
        </aside>
      </section>
    );
  }

  const title = viewTitles[view];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? "open" : ""}`}>
        <div className="brand"><span className="brand-mark">C</span><span><strong>CloudPen</strong><small>VALIDATION PLATFORM</small></span></div>
        <button className="workspace-card" onClick={() => setToast("Workspace switching is available to organization administrators.")}>
          <span className="workspace-avatar">NS</span><span><strong>Northstar Labs</strong><small>Enterprise workspace</small></span><span>⌄</span>
        </button>
        <nav aria-label="Primary navigation">
          <span className="nav-label">WORKSPACE</span>
          {navigation.map((item) => <button key={item.key} className={view === item.key ? "active" : ""} onClick={() => chooseView(item.key)}><span className="nav-icon">{item.icon}</span>{item.label}{item.key === "paths" && <span className="nav-count">16</span>}</button>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="runner-health"><div><span className="pulse paused" /><strong>Runner disabled</strong></div><p>Fail-closed · provisioning required</p></div>
          <button onClick={() => setToast("Help center opened in a new support panel.")}><span className="nav-icon">?</span> Help & documentation</button>
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
              {noticeOpen && <div className="popover notification-popover"><span className="section-kicker">NOTIFICATIONS</span><strong>Validation coverage improved</strong><p>Eight IAM paths were revalidated successfully.</p><button onClick={() => { setNoticeOpen(false); setView("runs"); }}>View run history</button></div>}
            </div>
            <div className="popover-anchor">
              <button className="avatar-button" aria-label="Open profile menu" onClick={() => setProfileOpen((open) => !open)}>{initials(currentUser.displayName)}</button>
              {profileOpen && <div className="popover profile-popover"><strong>{currentUser.displayName}</strong><span>{currentUser.role} · {currentUser.email}</span>{currentUser.localDevelopment && <span>Loopback development identity</span>}<a href="/signout-with-chatgpt?return_to=%2F">Sign out</a></div>}
            </div>
          </div>
        </header>

        <main>
          <div className="page-heading">
            <div><span className="page-eyebrow">{title.eyebrow}</span><h1>{title.title}</h1><p>{title.description}</p></div>
            <div className="heading-actions"><button className="button secondary" disabled={!canConnect} title={!canConnect ? "Operator or administrator role required" : undefined} onClick={() => setModal("connect")}>＋ Connect account</button><button className="button primary" disabled={!canPlan} title={!canPlan ? "Operator or administrator role required" : undefined} onClick={() => openValidation()}>▶ New validation</button></div>
          </div>
          {view === "overview" && renderOverview()}
          {view === "paths" && renderPaths()}
          {view === "assets" && renderAssets()}
          {view === "runs" && renderRuns()}
          {view === "guardrails" && renderGuardrails()}
        </main>
      </div>

      <nav className="mobile-bottom-nav" aria-label="Mobile navigation">
        {navigation.slice(0, 4).map((item) => <button key={item.key} className={view === item.key ? "active" : ""} onClick={() => chooseView(item.key)}><span>{item.icon}</span>{item.label.split(" ")[0]}</button>)}
      </nav>

      {modal && <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) setModal(null); }}>
        <section className="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <button className="modal-close" aria-label="Close dialog" onClick={() => setModal(null)}>×</button>
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
            <div className="connection-note"><span>i</span><p>The next step generates a CloudFormation template for the least-privilege read-only role.</p></div>
            <div className="modal-actions"><button type="button" className="button secondary" onClick={() => setModal(null)}>Cancel</button><button className="button primary" type="submit">Generate connector</button></div>
          </form>}
          {modal === "remediate" && <>
            <span className="section-kicker">ROOT-CAUSE REMEDIATION</span><h2 id="modal-title">Restrict the risky permission</h2><p className="modal-intro">This recommendation closes the shortest validated route while preserving the approved deployment workflow.</p>
            <div className="remediation-block"><span>WHY THIS FIX</span><p>{selectedPath.remediation}</p></div>
            <pre className="policy-code"><code>{`{
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
}`}</code></pre>
            <div className="modal-actions"><button className="button secondary" onClick={() => setModal(null)}>Close</button><button className="button primary" onClick={() => { setModal(null); setToast("Remediation draft copied to the engineering queue."); }}>Create remediation draft</button></div>
          </>}
        </section>
      </div>}

      {toast && <div className="toast" role="status"><span>✓</span>{toast}</div>}
    </div>
  );
}
