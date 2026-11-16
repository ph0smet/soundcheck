import { guarded, readJson } from "@/lib/server/http";
import { MAX_RBAC_BODY_BYTES, runRbac } from "@/lib/server/rbac";
export async function POST(request: Request) {
  return guarded(request, async () => Response.json(await runRbac(await readJson(request, MAX_RBAC_BODY_BYTES), request.signal), {headers:{"cache-control":"no-store"}}));
}
