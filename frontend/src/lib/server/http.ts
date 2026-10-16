// The HTTP trust boundary for the web adapter. The service has no
// authentication: it is meant for one operator on their own machine. These
// checks keep it that way:
//
// - Host allow-list: requests must name an allowed host, which defeats DNS
//   rebinding against a server bound to localhost.
// - Same-origin writes: a POST from another site (Origin or Sec-Fetch-Site says
//   cross-site) is refused, so a web page cannot drive the verifier.
// - Size limits enforced while streaming: an oversized body is rejected before
//   it is buffered, based on Content-Length when declared and on bytes read
//   otherwise.
//
// Deployments that expose the service beyond localhost must put their own
// authentication in front of it and list their host in SOUNDCHECK_ALLOWED_HOSTS.

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

const DEFAULT_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

export function allowedHosts(env: string | undefined = process.env.SOUNDCHECK_ALLOWED_HOSTS): string[] {
  const extra = (env ?? "")
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean);
  return [...DEFAULT_HOSTS, ...extra];
}

/** The host part of a Host header or URL authority, without the port. */
function hostname(authority: string) {
  const value = authority.trim().toLowerCase();
  if (value.startsWith("[")) return value.slice(0, value.indexOf("]") + 1);
  return value.split(":")[0];
}

export function checkRequestOrigin(request: Request, hosts: string[] = allowedHosts()) {
  const host = request.headers.get("host");
  if (!host || !hosts.includes(hostname(host))) {
    throw new HttpError(403, "This host is not allowed. Set SOUNDCHECK_ALLOWED_HOSTS to serve it.");
  }
  if (request.method === "GET" || request.method === "HEAD") return;
  if (request.headers.get("sec-fetch-site") === "cross-site") {
    throw new HttpError(403, "Cross-site requests are not allowed.");
  }
  const origin = request.headers.get("origin");
  if (origin !== null) {
    let originHost: string;
    try {
      originHost = new URL(origin).host;
    } catch {
      throw new HttpError(403, "Cross-site requests are not allowed.");
    }
    if (originHost.toLowerCase() !== host.trim().toLowerCase()) {
      throw new HttpError(403, "Cross-site requests are not allowed.");
    }
  }
}

/** Reads the body, refusing it as soon as it is known to exceed `maxBytes`. */
export async function readLimited(request: Request, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) throw new HttpError(400, "Invalid Content-Length.");
    if (length > maxBytes) throw new HttpError(413, `The request is larger than ${formatLimit(maxBytes)}.`);
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new HttpError(413, `The request is larger than ${formatLimit(maxBytes)}.`);
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function readJson(request: Request, maxBytes: number): Promise<unknown> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Expected application/json.");
  }
  const bytes = await readLimited(request, maxBytes);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new HttpError(400, "The request body is not valid JSON.");
  }
}

export async function readForm(request: Request, maxBytes: number): Promise<FormData> {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("multipart/form-data")) {
    throw new HttpError(415, "Expected a multipart form upload.");
  }
  const bytes = await readLimited(request, maxBytes);
  try {
    return await new Response(bytes, { headers: { "content-type": type } }).formData();
  } catch {
    throw new HttpError(400, "Expected a multipart form upload.");
  }
}

function formatLimit(bytes: number) {
  return bytes >= 1024 * 1024 ? `${Math.round(bytes / 1024 / 1024)} MB` : `${Math.round(bytes / 1024)} KB`;
}

/** Runs a route handler behind the origin check, mapping HttpError to a JSON response. */
export async function guarded(request: Request, handler: () => Promise<Response>): Promise<Response> {
  try {
    checkRequestOrigin(request);
    return await handler();
  } catch (error) {
    if (error instanceof HttpError) {
      // Shaped as an EngineFailure so verify/compare clients render it as "nothing was
      // verified"; `error` serves clients that only read a message.
      return Response.json(
        { ok: false, stage: "input", exitCode: null, message: error.message, error: error.message },
        { status: error.status, headers: { "cache-control": "no-store" } },
      );
    }
    throw error;
  }
}
