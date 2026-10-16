import type { VerifyRequest } from "@/lib/api";
import { guarded, readJson } from "@/lib/server/http";
import { MAX_DOCUMENT_BYTES, runVerify } from "@/lib/server/operations";

// A config and a contract, each at most MAX_DOCUMENT_BYTES, plus JSON escaping.
const MAX_BODY_BYTES = 4 * MAX_DOCUMENT_BYTES;

export async function POST(request: Request) {
  return guarded(request, async () => {
    const body = (await readJson(request, MAX_BODY_BYTES)) as Partial<VerifyRequest>;
    return Response.json(await runVerify(body ?? {}, request.signal), { headers: { "cache-control": "no-store" } });
  });
}
