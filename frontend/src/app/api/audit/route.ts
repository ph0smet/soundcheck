import { AuditInputError, auditStream, prepareAudit } from "@/lib/server/audit";

export async function POST(request: Request) {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return Response.json({ error: "Expected a multipart form upload." }, { status: 400 });
  }
  try {
    const prepared = await prepareAudit(form);
    return new Response(auditStream(prepared, request.signal), {
      headers: { "content-type": "application/x-ndjson; charset=utf-8", "cache-control": "no-store" },
    });
  } catch (error) {
    if (error instanceof AuditInputError) {
      return Response.json({ error: error.message }, { status: 400 });
    }
    throw error;
  }
}
