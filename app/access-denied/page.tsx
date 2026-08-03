import { chatGPTSignOutPath } from "../chatgpt-auth";

export default function AccessDenied() {
  return (
    <main style={{ maxWidth: 620, margin: "10vh auto", padding: 32 }}>
      <p className="section-kicker">ACCESS DENIED</p>
      <h1>This identity is not a CloudPen workspace member.</h1>
      <p>Ask a workspace administrator to add your email to an application role. Sites access alone does not grant CloudPen authorization.</p>
      <a className="button secondary" href={chatGPTSignOutPath("/")}>Sign out</a>
    </main>
  );
}
