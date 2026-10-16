import type { Metadata } from "next";
import { connection } from "next/server";

import { ProfileView } from "@/components/profile/profile-view";
import { Failure, OfflineHint } from "@/components/results/states";
import { PageHeader } from "@/components/ui";
import { loadProfile } from "@/lib/server/operations";

export const metadata: Metadata = { title: "Assurance profile" };

export default async function ProfilePage() {
  await connection();
  const result = await loadProfile();

  return (
    <div>
      <PageHeader
        title="Assurance profile"
        description="The versioned boundary of Kong semantics Soundcheck models. Every report names this profile, so a proof always says exactly what it covers."
      />
      {result.ok ? (
        <ProfileView profile={result.profile} />
      ) : (
        <div className="max-w-2xl space-y-4 p-4 md:p-6">
          <Failure failure={result} />
          <OfflineHint />
        </div>
      )}
    </div>
  );
}
