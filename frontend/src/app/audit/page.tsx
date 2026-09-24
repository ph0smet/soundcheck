import type { Metadata } from "next";

import { AuditWorkspace } from "@/components/audit/audit-workspace";
import { loadSamples } from "@/lib/server/corpus";

export const metadata: Metadata = { title: "Audit" };

export default async function AuditPage() {
  const { contracts } = await loadSamples();
  return <AuditWorkspace contracts={contracts} />;
}
