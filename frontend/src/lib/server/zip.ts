// A strict ZIP reader for audit uploads.
//
// The audit must verify exactly the bytes the uploader packed. A lenient reader
// that trusts an entry's declared size can silently hand the verifier a
// truncated prefix of a config (and so a proof about different bytes). This
// reader therefore rejects any archive whose structure is inconsistent, and
// accepts an entry only when its actual decompressed bytes match both the
// declared size and the CRC-32. Limits are enforced on actual output, while
// inflating, never on declared sizes alone.
//
// Supported: one-disk archives, stored (0) and deflate (8) entries, data
// descriptors. Rejected: ZIP64, encryption, multi-disk, other methods,
// duplicate names, overlapping entries, and local/central header mismatches.

import { inflateRawSync } from "node:zlib";

export class ZipError extends Error {}

export interface ZipLimits {
  /** Maximum number of non-directory entries. */
  entries: number;
  /** Entries whose declared size exceeds this are listed but not inflated. */
  fileBytes: number;
  /** Maximum total actual decompressed bytes across all inflated entries. */
  totalBytes: number;
}

export type ZipEntry =
  | { path: string; status: "read"; data: Uint8Array }
  /** Declared larger than the per-file limit, so it was not inflated. */
  | { path: string; status: "too-large"; declaredBytes: number };

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const EOCD_SIZE = 22;
const CENTRAL_SIZE = 46;
const LOCAL_SIZE = 30;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

interface Central {
  name: string;
  nameBytes: Uint8Array;
  flags: number;
  method: number;
  crc: number;
  compressedSize: number;
  size: number;
  localOffset: number;
}

function findEndOfCentralDirectory(view: DataView): number {
  const last = view.byteLength - EOCD_SIZE;
  const first = Math.max(0, last - 0xffff);
  for (let offset = last; offset >= first; offset--) {
    if (view.getUint32(offset, true) !== SIG_EOCD) continue;
    // The comment must run exactly to the end; anything else is trailing data.
    if (offset + EOCD_SIZE + view.getUint16(offset + 20, true) === view.byteLength) return offset;
  }
  throw new ZipError("not a ZIP archive (no end-of-central-directory record)");
}

function sameBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/**
 * Inflates `input` to at most `limit` bytes. zlib stops producing output at the
 * limit (in small chunks), so memory stays bounded by the limit however much the
 * compressed data claims to expand; one byte of headroom detects an overrun.
 */
function inflateBounded(input: Uint8Array, limit: number, path: string): Uint8Array {
  try {
    return inflateRawSync(input, { maxOutputLength: limit + 1, chunkSize: 16 * 1024 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE") {
      throw new ZipError(`${path}: decompresses to more than its declared size`);
    }
    throw new ZipError(`${path}: corrupt or truncated compressed data (${(error as Error).message})`);
  }
}

export function readZip(bytes: Uint8Array, limits: ZipLimits): ZipEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.byteLength < EOCD_SIZE) throw new ZipError("not a ZIP archive (too short)");
  const eocd = findEndOfCentralDirectory(view);

  const disk = view.getUint16(eocd + 4, true);
  const centralDisk = view.getUint16(eocd + 6, true);
  const diskEntries = view.getUint16(eocd + 8, true);
  const totalEntries = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (totalEntries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new ZipError("ZIP64 archives are not supported");
  }
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== totalEntries) {
    throw new ZipError("multi-disk archives are not supported");
  }
  if (centralOffset + centralSize !== eocd) {
    throw new ZipError("the central directory does not end where the archive says it does");
  }

  const decoder = new TextDecoder("utf-8", { fatal: false });
  const centrals: Central[] = [];
  let cursor = centralOffset;
  for (let index = 0; index < totalEntries; index++) {
    if (cursor + CENTRAL_SIZE > eocd || view.getUint32(cursor, true) !== SIG_CENTRAL) {
      throw new ZipError("malformed central directory");
    }
    const nameLength = view.getUint16(cursor + 28, true);
    const extraLength = view.getUint16(cursor + 30, true);
    const commentLength = view.getUint16(cursor + 32, true);
    const next = cursor + CENTRAL_SIZE + nameLength + extraLength + commentLength;
    if (next > eocd) throw new ZipError("malformed central directory");
    const nameBytes = bytes.subarray(cursor + CENTRAL_SIZE, cursor + CENTRAL_SIZE + nameLength);
    const entry: Central = {
      name: decoder.decode(nameBytes),
      nameBytes,
      flags: view.getUint16(cursor + 8, true),
      method: view.getUint16(cursor + 10, true),
      crc: view.getUint32(cursor + 16, true),
      compressedSize: view.getUint32(cursor + 20, true),
      size: view.getUint32(cursor + 24, true),
      localOffset: view.getUint32(cursor + 42, true),
    };
    if (entry.compressedSize === 0xffffffff || entry.size === 0xffffffff || entry.localOffset === 0xffffffff) {
      throw new ZipError(`${entry.name}: ZIP64 entries are not supported`);
    }
    if (entry.flags & 0x41) throw new ZipError(`${entry.name}: encrypted entries are not supported`);
    centrals.push(entry);
    cursor = next;
  }
  if (cursor !== eocd) throw new ZipError("the central directory has trailing data");

  const names = new Set<string>();
  for (const entry of centrals) {
    if (names.has(entry.name)) throw new ZipError(`duplicate entry name: ${entry.name}`);
    names.add(entry.name);
  }
  const files = centrals.filter((entry) => !entry.name.endsWith("/"));
  if (files.length > limits.entries) throw new ZipError(`the archive has more than ${limits.entries} files`);

  // Entries must occupy disjoint ranges before the central directory, so no
  // byte is shared between two files (a classic decompression-bomb trick).
  const ranges: { start: number; end: number; name: string }[] = [];
  const located = centrals.map((entry) => {
    const at = entry.localOffset;
    if (at + LOCAL_SIZE > centralOffset || view.getUint32(at, true) !== SIG_LOCAL) {
      throw new ZipError(`${entry.name}: missing or misplaced local header`);
    }
    const localFlags = view.getUint16(at + 6, true);
    const localMethod = view.getUint16(at + 8, true);
    const nameLength = view.getUint16(at + 26, true);
    const extraLength = view.getUint16(at + 28, true);
    const localName = bytes.subarray(at + LOCAL_SIZE, at + LOCAL_SIZE + nameLength);
    if (!sameBytes(localName, entry.nameBytes)) {
      throw new ZipError(`${entry.name}: local and central headers name different files`);
    }
    if (localMethod !== entry.method || (localFlags & 0x41) !== 0) {
      throw new ZipError(`${entry.name}: local and central headers disagree`);
    }
    // Without a data descriptor (bit 3) the local header repeats the CRC and sizes.
    if (!(localFlags & 0x08)) {
      if (
        view.getUint32(at + 14, true) !== entry.crc ||
        view.getUint32(at + 18, true) !== entry.compressedSize ||
        view.getUint32(at + 22, true) !== entry.size
      ) {
        throw new ZipError(`${entry.name}: local and central headers disagree on size or checksum`);
      }
    }
    const dataStart = at + LOCAL_SIZE + nameLength + extraLength;
    const dataEnd = dataStart + entry.compressedSize;
    if (dataEnd > centralOffset) throw new ZipError(`${entry.name}: data runs past the end of the archive`);
    ranges.push({ start: at, end: dataEnd, name: entry.name });
    return { entry, dataStart, dataEnd };
  });
  ranges.sort((a, b) => a.start - b.start);
  for (let i = 1; i < ranges.length; i++) {
    if (ranges[i].start < ranges[i - 1].end) {
      throw new ZipError(`${ranges[i].name}: overlaps ${ranges[i - 1].name}`);
    }
  }

  let total = 0;
  const out: ZipEntry[] = [];
  for (const { entry, dataStart, dataEnd } of located) {
    if (entry.name.endsWith("/")) continue;
    if (entry.size > limits.fileBytes) {
      out.push({ path: entry.name, status: "too-large", declaredBytes: entry.size });
      continue;
    }
    if (total + entry.size > limits.totalBytes) {
      throw new ZipError(`the archive expands to more than ${limits.totalBytes} bytes`);
    }
    const raw = bytes.subarray(dataStart, dataEnd);
    let data: Uint8Array;
    if (entry.method === 0) {
      if (entry.compressedSize !== entry.size) {
        throw new ZipError(`${entry.name}: stored entry sizes disagree`);
      }
      data = raw.slice();
    } else if (entry.method === 8) {
      // Bounded by the declared size: decompressing to more is an inconsistency.
      data = inflateBounded(raw, entry.size, entry.name);
    } else {
      throw new ZipError(`${entry.name}: compression method ${entry.method} is not supported`);
    }
    if (data.length !== entry.size) {
      throw new ZipError(`${entry.name}: decompresses to ${data.length} bytes, but the archive declares ${entry.size}`);
    }
    if (crc32(data) !== entry.crc) throw new ZipError(`${entry.name}: checksum mismatch`);
    total += data.length;
    out.push({ path: entry.name, status: "read", data });
  }
  return out;
}
