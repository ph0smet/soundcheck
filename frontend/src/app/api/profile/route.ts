import { connection } from "next/server";

import { loadProfile } from "@/lib/server/operations";

export async function GET() {
  await connection();
  return Response.json(await loadProfile());
}
