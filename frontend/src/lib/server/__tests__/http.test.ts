import { describe, expect, it } from "vitest";

import { checkRequestOrigin, guarded, HttpError, readJson, readLimited } from "../http";

const HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function request(headers: Record<string, string>, init: RequestInit = {}) {
  return new Request("http://localhost:3000/api/verify", { method: "POST", headers, ...init });
}

function status(fn: () => unknown) {
  try {
    fn();
    return 200;
  } catch (error) {
    return error instanceof HttpError ? error.status : 500;
  }
}

describe("checkRequestOrigin", () => {
  it("allows same-origin requests to localhost", () => {
    expect(status(() => checkRequestOrigin(request({ host: "localhost:3000", origin: "http://localhost:3000" }), HOSTS))).toBe(200);
    expect(status(() => checkRequestOrigin(request({ host: "127.0.0.1:3000" }), HOSTS))).toBe(200);
    expect(status(() => checkRequestOrigin(request({ host: "[::1]:3000" }), HOSTS))).toBe(200);
  });

  it("rejects a rebound DNS name pointing at localhost", () => {
    expect(status(() => checkRequestOrigin(request({ host: "attacker.example:3000" }), HOSTS))).toBe(403);
  });

  it("rejects a missing Host header", () => {
    expect(status(() => checkRequestOrigin(request({}), HOSTS))).toBe(403);
  });

  it("rejects cross-site writes", () => {
    expect(status(() => checkRequestOrigin(request({ host: "localhost:3000", origin: "https://evil.example" }), HOSTS))).toBe(403);
    expect(status(() => checkRequestOrigin(request({ host: "localhost:3000", "sec-fetch-site": "cross-site" }), HOSTS))).toBe(403);
    expect(status(() => checkRequestOrigin(request({ host: "localhost:3000", origin: "null" }), HOSTS))).toBe(403);
  });

  it("rejects a different port on the same host", () => {
    expect(status(() => checkRequestOrigin(request({ host: "localhost:3000", origin: "http://localhost:8080" }), HOSTS))).toBe(403);
  });
});

function streamOf(chunks: number, size: number) {
  let sent = 0;
  let pulled = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled++;
      if (sent >= chunks) return controller.close();
      sent++;
      controller.enqueue(new Uint8Array(size));
    },
  });
  return { stream, pulled: () => pulled };
}

describe("readLimited", () => {
  it("rejects an oversized declared Content-Length before reading", async () => {
    const body = streamOf(100, 1024);
    const req = new Request("http://localhost/api", {
      method: "POST",
      headers: { "content-length": String(10 * 1024 * 1024) },
      body: body.stream,
      duplex: "half",
    } as RequestInit);
    await expect(readLimited(req, 1024 * 1024)).rejects.toMatchObject({ status: 413 });
    expect(body.pulled()).toBeLessThanOrEqual(1);
  });

  it("stops reading an undeclared body as soon as it exceeds the limit", async () => {
    const body = streamOf(10_000, 64 * 1024);
    const req = new Request("http://localhost/api", { method: "POST", body: body.stream, duplex: "half" } as RequestInit);
    await expect(readLimited(req, 256 * 1024)).rejects.toMatchObject({ status: 413 });
    expect(body.pulled()).toBeLessThan(20);
  });

  it("returns a body within the limit", async () => {
    const req = new Request("http://localhost/api", { method: "POST", body: "hello" });
    expect(new TextDecoder().decode(await readLimited(req, 1024))).toBe("hello");
  });
});

describe("readJson", () => {
  it("requires a JSON content type", async () => {
    const req = new Request("http://localhost/api", { method: "POST", body: "{}", headers: { "content-type": "text/plain" } });
    await expect(readJson(req, 1024)).rejects.toMatchObject({ status: 415 });
  });

  it("rejects malformed JSON", async () => {
    const req = new Request("http://localhost/api", {
      method: "POST",
      body: "{",
      headers: { "content-type": "application/json" },
    });
    await expect(readJson(req, 1024)).rejects.toMatchObject({ status: 400 });
  });
});

describe("guarded", () => {
  it("answers a rejected request with a failure body, never a verdict", async () => {
    const response = await guarded(request({ host: "evil.example" }), async () => new Response("unreachable"));
    expect(response.status).toBe(403);
    const body = await response.json();
    expect(body).toMatchObject({ ok: false, stage: "input" });
  });
});
