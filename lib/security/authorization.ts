import { headers } from "next/headers";
import { getChatGPTUser, type ChatGPTUser } from "../../app/chatgpt-auth";
import { roleForEmail, runtimeBindings, type CloudPenRole } from "./runtime";

export type AuthorizedUser = ChatGPTUser & {
  role: CloudPenRole;
  localDevelopment: boolean;
};

const roleCapabilities: Record<CloudPenRole, ReadonlySet<string>> = {
  admin: new Set(["read", "plan", "approve", "configure", "connect", "enroll"]),
  operator: new Set(["read", "plan", "connect"]),
  reviewer: new Set(["read", "approve"]),
  viewer: new Set(["read"]),
};

export async function getAuthorizedUser(): Promise<AuthorizedUser | null> {
  const identity = await getChatGPTUser();
  if (identity) {
    const role = roleForEmail(identity.email);
    return role ? { ...identity, role, localDevelopment: false } : null;
  }

  const localMode = process.env.NODE_ENV === "development" || runtimeBindings().CLOUDPEN_LOCAL_MODE === "1";
  if (!localMode) return null;
  const requestHeaders = await headers();
  const hostname = (requestHeaders.get("host") ?? "").split(":", 1)[0];
  if (hostname !== "127.0.0.1" && hostname !== "localhost" && hostname !== "[::1]") return null;

  const email = runtimeBindings().CLOUDPEN_LOCAL_DEV_EMAIL?.trim() || "local-admin@cloudpen.invalid";
  return {
    displayName: "Local security administrator",
    email,
    fullName: "Local security administrator",
    role: "admin",
    localDevelopment: true,
  };
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
