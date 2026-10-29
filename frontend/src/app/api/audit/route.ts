import { AUDIT_LIMITS, AuditInputError, auditStream, prepareAudit } from "@/lib/server/audit";
import { guarded, HttpError, readForm } from "@/lib/server/http";

// The upload limit plus room for the multipart envelope and the small text fields.
const MAX_BODY_BYTES = AUDIT_LIMITS.uploadBytes + AUDIT_LIMITS.contractBytes + 256 * 1024;

export async function POST(request: Request) {
  return guarded(request, async () => {
    const form = await readForm(request, MAX_BODY_BYTES);
    try {
      const prepared = await prepareAudit(form, request.signal);
      return new Response(auditStream(prepared, request.signal), {
        headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" },
      });
    } catch (error) {
      if (error instanceof AuditInputError) throw new HttpError(400, error.message);
      throw error;
    }
  });
}
