import { headers } from "next/headers";
import { getChatGPTUser, type ChatGPTUser } from "../../app/chatgpt-auth";
import { LOCAL_IDENTITY_VERIFIED_HEADER, WORKSPACE_CONTEXT_HEADER } from "./headers";
import { configuredWorkspaceId, roleForEmail, runtimeBindings, type CloudPenRole } from "./runtime";

export type AuthorizedUser = ChatGPTUser & {
  role: CloudPenRole;
  workspaceId: string;
  localDevelopment: boolean;
};

const roleCapabilities: Record<CloudPenRole, ReadonlySet<string>> = {
  admin: new Set(["read", "plan", "approve", "configure", "connect", "enroll", "accept-risk", "close-remediation"]),
  operator: new Set(["read", "plan", "connect"]),
  reviewer: new Set(["read", "approve", "close-remediation"]),
  viewer: new Set(["read"]),
};

export async function getAuthorizedUser(): Promise<AuthorizedUser | null> {
  const requestHeaders = await headers();
  const identity = await getChatGPTUser();
  if (identity) {
    const membership = await resolveMembership(identity.email, requestHeaders.get(WORKSPACE_CONTEXT_HEADER));
    return membership ? { ...identity, ...membership, localDevelopment: false } : null;
  }

  const localMode = runtimeBindings().CLOUDPEN_LOCAL_MODE === "1";
  if (!localMode) return null;
  if (requestHeaders.get(LOCAL_IDENTITY_VERIFIED_HEADER) !== "1") return null;

  const email = runtimeBindings().CLOUDPEN_LOCAL_DEV_EMAIL?.trim() || "local-admin@cloudpen.invalid";
  return {
    displayName: "Local security administrator",
    email,
    fullName: "Local security administrator",
    role: "admin",
    workspaceId: configuredWorkspaceId(),
    localDevelopment: true,
  };
}

async function resolveMembership(
  email: string,
  requestedWorkspace: string | null,
): Promise<{ role: CloudPenRole; workspaceId: string } | null> {
  const normalizedEmail = email.trim().toLowerCase();
  const requested = requestedWorkspace?.trim() || null;
  if (requested && !/^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(requested)) return null;

  const { DB } = runtimeBindings();
  if (DB) {
    const result = await DB.prepare(`SELECT workspace_id, role FROM memberships
      WHERE lower(email) = ? ORDER BY workspace_id LIMIT 101`)
      .bind(normalizedEmail)
      .all<{ workspace_id: string; role: CloudPenRole }>();
    if (result.results.length > 100) return null;
    const selected = requested
      ? result.results.find((row) => row.workspace_id === requested)
      : result.results.length === 1
        ? result.results[0]
        : result.results.find((row) => row.workspace_id === configuredWorkspaceId());
    if (selected) return { role: selected.role, workspaceId: selected.workspace_id };
    if (result.results.length > 0 || requested) return null;
  } else if (requested && requested !== configuredWorkspaceId()) {
    return null;
  }

  const role = roleForEmail(normalizedEmail);
  return role ? { role, workspaceId: configuredWorkspaceId() } : null;
}

export async function requireCapability(capability: string): Promise<AuthorizedUser> {
  const user = await getAuthorizedUser();
  if (!user) throw new AuthorizationError(403, "Authenticated workspace membership is required.");
  if (!roleCapabilities[user.role].has(capability)) {
    throw new AuthorizationError(403, `The ${user.role} role cannot perform this action.`);
  }
  return user;
}

export class AuthorizationError extends Error {
  constructor(public readonly status: 401 | 403, message: string) {
    super(message);
  }
}
