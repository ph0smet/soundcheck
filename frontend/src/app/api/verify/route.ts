import { runVerify } from "@/lib/server/operations";

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({}));
  return Response.json(await runVerify(body));
}
