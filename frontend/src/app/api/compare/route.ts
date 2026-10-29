import type { CompareRequest } from "@/lib/api";
import { guarded, readJson } from "@/lib/server/http";
import { MAX_DOCUMENT_BYTES, runCompare } from "@/lib/server/operations";

// Two configs and an optional contract, plus JSON escaping.
const MAX_BODY_BYTES = 6 * MAX_DOCUMENT_BYTES;

export async function POST(request: Request) {
  return guarded(request, async () => {
    const body = (await readJson(request, MAX_BODY_BYTES)) as Partial<CompareRequest>;
    return Response.json(await runCompare(body ?? {}, request.signal), { headers: { "cache-control": "no-store" } });
  });
}
