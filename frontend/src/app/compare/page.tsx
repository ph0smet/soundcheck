import type { Metadata } from "next";

import { CompareWorkspace, type ComparePreset } from "@/components/compare/compare-workspace";
import { loadSamples } from "@/lib/server/corpus";

export const metadata: Metadata = { title: "Compare" };

export default async function ComparePage() {
  const { configs, contracts } = await loadSamples();
  const find = (id: string) => configs.find((sample) => sample.id === id)?.content;
  const contract = (id: string) => contracts.find((sample) => sample.id === id)?.content ?? null;

  const candidates: (Omit<ComparePreset, "before" | "after"> & { before?: string; after?: string })[] = [
    {
      id: "repair",
      title: "Repair an exposed admin route",
      description: "Unsafe config repaired with key-auth, checked against the frozen admin-get contract.",
      before: find("workflow:unsafe.yaml"),
      after: find("workflow:repaired.yaml"),
      mode: "decision",
      contract: contract("contract:admin-get.yaml"),
    },
    {
      id: "deny-all",
      title: "Deny-all is not a repair",
      description: "Removing every route blocks anonymous traffic but breaks the must-allow clause.",
      before: find("workflow:unsafe.yaml"),
      after: find("workflow:deny-all.yaml"),
      mode: "decision",
      contract: contract("contract:admin-get.yaml"),
    },
    {
      id: "decision-diff",
      title: "Adding auth changes decisions",
      description: "Open /admin versus key-auth protected /admin, compared on every modeled request.",
      before: find("case:admin-no-auth"),
      after: find("case:admin-key-auth"),
      mode: "decision",
      contract: null,
    },
    {
      id: "route-service",
      title: "Route-level versus service-level auth",
      description: "Route auth with an open legacy sibling versus auth inherited from the service.",
      before: find("case:auth-on-route-only"),
      after: find("case:auth-on-service"),
      mode: "route-service",
      contract: null,
    },
  ];
  const presets = candidates.filter((preset): preset is ComparePreset => Boolean(preset.before && preset.after));

  return <CompareWorkspace presets={presets} samples={configs} contracts={contracts} />;
}
