import { NextResponse, type NextRequest } from "next/server";

import { checkRequestOrigin, HttpError } from "@/lib/server/http";

// Applies the HTTP trust boundary's header checks (Host allow-list, same-origin
// writes) to every page, not only /api/*: server-rendered pages such as /profile
// also run the engine. Only headers are read here, so bodies are never buffered;
// the API routes keep their own checks and streaming size limits.
export function proxy(request: NextRequest) {
  try {
    checkRequestOrigin(request);
  } catch (error) {
    if (error instanceof HttpError) {
      return NextResponse.json(
        { ok: false, stage: "input", exitCode: null, message: error.message, error: error.message },
        { status: error.status, headers: { "cache-control": "no-store" } },
      );
    }
    throw error;
  }
  return NextResponse.next();
}

export const config = {
  // Static build assets carry no data and run nothing.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|icon.png|soundcheck-logo.png).*)"],
};
