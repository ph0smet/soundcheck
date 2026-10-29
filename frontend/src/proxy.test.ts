import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { proxy } from "./proxy";

describe("proxy", () => {
  it("lets same-host page requests through", () => {
    const response = proxy(new NextRequest("http://localhost:3000/profile", { headers: { host: "localhost:3000" } }));
    expect(response.status).toBe(200);
  });

  it("refuses pages requested under a foreign host (DNS rebinding)", async () => {
    const response = proxy(new NextRequest("http://localhost:3000/profile", { headers: { host: "attacker.example" } }));
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ ok: false, stage: "input" });
  });
});
