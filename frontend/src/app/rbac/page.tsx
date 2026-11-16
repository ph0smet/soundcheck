import type { Metadata } from "next";

import { RbacWorkspace } from "@/components/rbac/workspace";
import { loadRbacExamples } from "@/lib/server/rbac";

export const metadata: Metadata = { title: "Kubernetes RBAC" };

export default async function RbacPage() {
  return <RbacWorkspace examples={await loadRbacExamples()} />;
}
