import { redirect } from "next/navigation";
import CloudPenDashboard from "./cloudpen-dashboard";
import { chatGPTSignInPath, getChatGPTUser } from "./chatgpt-auth";
import { getAuthorizedUser } from "../lib/security/authorization";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await getAuthorizedUser();
  if (!user) {
    const identity = await getChatGPTUser();
    if (!identity) redirect(chatGPTSignInPath("/"));
    redirect("/access-denied");
  }

  return <CloudPenDashboard currentUser={{
    displayName: user.displayName,
    email: user.email,
    role: user.role,
    localDevelopment: user.localDevelopment,
  }} />;
}
