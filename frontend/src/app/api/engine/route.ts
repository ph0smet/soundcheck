import { connection } from "next/server";

import { engineStatus } from "@/lib/server/engine";

export async function GET() {
  await connection();
  return Response.json(await engineStatus());
}
