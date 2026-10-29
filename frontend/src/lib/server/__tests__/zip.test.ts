import { zipSync, strToU8 } from "fflate";
import { describe, expect, it } from "vitest";

import { extractZip } from "../audit";
import { crc32, readZip, ZipError } from "../zip";

const LIMITS = { entries: 100, fileBytes: 512 * 1024, totalBytes: 10 * 1024 * 1024 };

// A config whose decisive part (an unsupported plugin) sits after the first
// 171 bytes, as in the review's reproduction: a truncated prefix looks safe.
const SAFE_PREFIX = '_format_version: "3.0"\nservices:\n  - name: admin-api\n    url: http://admin.internal\n    routes:\n      - name: admin\n        paths: [/admin]\n        plugins:\n';
const CONFIG = `${SAFE_PREFIX}          - name: key-auth\n${"          # padding\n".repeat(480)}          - name: some-unsupported-plugin\n`;

function zip(files: Record<string, string>, level: 0 | 6 = 6) {
  return zipSync(Object.fromEntries(Object.entries(files).map(([name, text]) => [name, [strToU8(text), { level }]])));
}

/** Offsets of the (first) local and central headers in an fflate archive. */
function headers(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let central = -1;
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x02014b50) central = i;
    if (view.getUint32(i, true) === 0x06054b50) {
      central = view.getUint32(i + 16, true);
      break;
    }
  }
  return { view, local: 0, central };
}

describe("readZip", () => {
  it("reads a well-formed archive byte for byte", () => {
    const entries = readZip(zip({ "kong.yaml": CONFIG, "notes/readme.md": "hi" }), LIMITS);
    const kong = entries.find((entry) => entry.path === "kong.yaml");
    expect(kong?.status).toBe("read");
    if (kong?.status === "read") expect(new TextDecoder().decode(kong.data)).toBe(CONFIG);
    expect(entries).toHaveLength(2);
  });

  it("rejects a shrunken declared size instead of auditing a truncated prefix (review repro)", () => {
    const bytes = zip({ "kong.yaml": CONFIG });
    const { view, local, central } = headers(bytes);
    // Change only the declared uncompressed size, in both headers, to the safe prefix length.
    view.setUint32(local + 22, SAFE_PREFIX.length, true);
    view.setUint32(central + 24, SAFE_PREFIX.length, true);
    expect(() => readZip(bytes, LIMITS)).toThrow(ZipError);
    expect(() => extractZip(bytes)).toThrow(/rejected/);
  });

  it("rejects an inflated declared size", () => {
    const bytes = zip({ "kong.yaml": CONFIG });
    const { view, local, central } = headers(bytes);
    view.setUint32(local + 22, CONFIG.length + 10, true);
    view.setUint32(central + 24, CONFIG.length + 10, true);
    expect(() => readZip(bytes, LIMITS)).toThrow(/declares/);
  });

  it("rejects a checksum mismatch", () => {
    const bytes = zip({ "kong.yaml": CONFIG });
    const { view, local, central } = headers(bytes);
    const wrong = (crc32(strToU8(CONFIG)) ^ 1) >>> 0;
    view.setUint32(local + 14, wrong, true);
    view.setUint32(central + 16, wrong, true);
    expect(() => readZip(bytes, LIMITS)).toThrow(/checksum/);
  });

  it("rejects local and central headers that disagree", () => {
    const bytes = zip({ "kong.yaml": CONFIG });
    const { view, local } = headers(bytes);
    view.setUint32(local + 22, SAFE_PREFIX.length, true);
    expect(() => readZip(bytes, LIMITS)).toThrow(/disagree/);
  });

  it("rejects a stored entry whose declared size was changed", () => {
    const bytes = zip({ "kong.yaml": CONFIG }, 0);
    const { view, local, central } = headers(bytes);
    for (const at of [local + 18, local + 22]) view.setUint32(at, SAFE_PREFIX.length, true);
    for (const at of [central + 20, central + 24]) view.setUint32(at, SAFE_PREFIX.length, true);
    expect(() => readZip(bytes, LIMITS)).toThrow(ZipError);
  });

  it("stops inflating at the declared size instead of allocating the whole expansion (review repro)", () => {
    // 32 MB of zeros compresses to a few KB; declare it as a 1 KB entry.
    const bomb = zipSync({ "kong.yaml": [new Uint8Array(32 * 1024 * 1024), { level: 9 }] });
    const { view, local, central } = headers(bomb);
    view.setUint32(local + 22, 1024, true);
    view.setUint32(central + 24, 1024, true);
    const before = process.memoryUsage().arrayBuffers;
    expect(() => readZip(bomb, LIMITS)).toThrow(/more than its declared size/);
    // Output is capped while decompressing, so nothing near 32 MB is ever allocated.
    expect(process.memoryUsage().arrayBuffers - before).toBeLessThan(4 * 1024 * 1024);
  });

  it("enforces the total limit on actual output", () => {
    const big = "a".repeat(200_000);
    const bytes = zip({ "a.yaml": big, "b.yaml": big });
    expect(() => readZip(bytes, { ...LIMITS, totalBytes: 300_000 })).toThrow(/expands/);
  });

  it("lists, without inflating, entries declared over the per-file limit", () => {
    const entries = readZip(zip({ "huge.yaml": "a".repeat(2000) }), { ...LIMITS, fileBytes: 1000 });
    expect(entries).toEqual([{ path: "huge.yaml", status: "too-large", declaredBytes: 2000 }]);
  });

  it("rejects too many entries, garbage and truncated archives", () => {
    const many = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`f${i}.yaml`, "x"]));
    expect(() => readZip(zip(many), { ...LIMITS, entries: 4 })).toThrow(/more than 4/);
    expect(() => readZip(strToU8("not a zip at all, just text"), LIMITS)).toThrow(ZipError);
    const bytes = zip({ "kong.yaml": CONFIG });
    expect(() => readZip(bytes.subarray(0, bytes.length - 10), LIMITS)).toThrow(ZipError);
  });
});

describe("extractZip", () => {
  it("lists hidden files instead of silently dropping them, ignoring only macOS metadata", () => {
    const entries = extractZip(zip({ ".kong.yaml": CONFIG, ".DS_Store": "x", "__MACOSX/._kong.yaml": "x" }));
    expect(entries.map((entry) => entry.path)).toEqual([".kong.yaml"]);
  });
});
