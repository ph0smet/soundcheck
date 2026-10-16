import { connection } from "next/server";

import { engineStatus } from "@/lib/server/engine";
import { guarded } from "@/lib/server/http";

export async function GET(request: Request) {
  await connection();
  return guarded(request, async () => Response.json(await engineStatus()));
}
