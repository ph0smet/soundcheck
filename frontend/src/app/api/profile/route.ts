import { connection } from "next/server";

import { guarded } from "@/lib/server/http";
import { loadProfile } from "@/lib/server/operations";

export async function GET(request: Request) {
  await connection();
  return guarded(request, async () => Response.json(await loadProfile(request.signal)));
}
