import type { Metadata } from "next";

import { VerifyWorkspace, type VerifyInitial } from "@/components/verify/verify-workspace";
import { getCase, loadSamples } from "@/lib/server/corpus";

export const metadata: Metadata = { title: "Verify" };

const FALLBACK_CONFIG = `_format_version: "3.0"
services:
  - name: admin-api
    url: http://admin-backend
    routes:
      - name: admin-route
        paths:
          - /admin
`;

export default async function VerifyPage({ searchParams }: PageProps<"/verify">) {
  const { case: caseId } = await searchParams;
  const [samples, requested] = await Promise.all([
    loadSamples(),
    typeof caseId === "string" ? getCase(caseId) : null,
  ]);

  const starter = requested ?? (await getCase("admin-no-auth"));
  const initial: VerifyInitial = starter
    ? { config: starter.config, spec: starter.spec, origin: requested ? `case:${starter.id}` : null }
    : { config: FALLBACK_CONFIG, spec: { mode: "property", property: "no-anonymous-access", pathPrefix: "/admin" }, origin: null };

  return (
    <VerifyWorkspace
      key={initial.origin ?? "default"}
      initial={initial}
      samples={samples.configs}
      contracts={samples.contracts}
    />
  );
}
