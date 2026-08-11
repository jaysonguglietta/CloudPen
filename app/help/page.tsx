import { redirect } from "next/navigation";
import { chatGPTSignInPath, getChatGPTUser } from "../chatgpt-auth";
import { getAuthorizedUser } from "../../lib/security/authorization";

export const dynamic = "force-dynamic";

const guides = [
  ["Architecture", "Trust boundaries, components, and request flows", "docs/architecture.md"],
  ["API reference", "Authenticated control-plane routes and request contracts", "docs/api.md"],
  ["Operations", "Local operation, incident response, retention, and recovery", "docs/operations.md"],
  ["Runner security", "Mandatory controls before cloud execution can be enabled", "docs/runner-security-design.md"],
  ["Security review", "Threat model, findings, and accepted limitations", "docs/security-review.md"],
] as const;

export default async function HelpPage() {
  const user = await getAuthorizedUser();
  if (!user) {
    const identity = await getChatGPTUser();
    if (!identity) redirect(chatGPTSignInPath("/help"));
    redirect("/access-denied");
  }
  return <main className="help-shell"><a className="back-link" href="/">← Back to CloudPen</a><span className="page-eyebrow">PRODUCT DOCUMENTATION</span><h1>Operate CloudPen with evidence, authorization, and restraint.</h1><p>The current release is a non-executable control plane. Use these guides to understand which records are authoritative, how plans are signed, and what must be true before a customer-hosted runner is trusted.</p><div className="help-grid">{guides.map(([title, description, path]) => <a key={path} href={`https://github.com/jaysonguglietta/CloudPen/blob/main/${path}`} target="_blank" rel="noreferrer"><span className="section-kicker">GUIDE</span><h2>{title}</h2><p>{description}</p><strong>Open guide ↗</strong></a>)}</div><section className="help-boundary"><h2>Safety boundary</h2><p>Signed plans, approvals, connector requests, discovery plans, and runner enrollment records are administrative intent only. They cannot make AWS calls in this release.</p><code>executable: false</code></section></main>;
}
