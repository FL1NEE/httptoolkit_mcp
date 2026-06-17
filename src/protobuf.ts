/**
 * Schema-less protobuf inspector for reverse-engineering messy real-world APIs
 * (Spotify, YouTube, ...). Unlike `protoc --decode_raw`, every length-delimited
 * field keeps ALL viable interpretations at once - nested message, UTF-8 string,
 * raw bytes, and transparently decompressed (gzip/zlib/zstd) inner payloads - so
 * an agent can disambiguate instead of trusting one guess.
 */
import zlib from "node:zlib";

export interface PbNode {
  field: number;
  wire: number;
  // Scalars
  varint?: string;
  signed?: string; // zigzag-decoded view of the varint
  fixed64?: { hex: string; uint: string; int: string; double: number };
  fixed32?: { hex: string; uint: number; int: number; float: number };
  // Length-delimited interpretations (any/all may be present)
  length?: number;
  message?: PbNode[];
  string?: string;
  bytesHex?: string;
  decompressed?: { algo: string; message?: PbNode[]; string?: string; bytesHex?: string };
  /** A string field whose value is itself base64(url) protobuf (e.g. YouTube tokens). */
  base64Decoded?: PbNode[];
}

/** Normalize base64url -> base64 and pad, so url-safe tokens decode correctly. */
export function normalizeBase64(s: string): string {
  let t = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  while (t.length % 4) t += "=";
  return t;
}

/** If a string looks like base64(url) protobuf, decode + parse it; else null. */
function tryBase64Protobuf(s: string): PbNode[] | null {
  if (s.length < 16 || !/^[A-Za-z0-9_\-+/]+=*$/.test(s)) return null;
  try {
    const buf = Buffer.from(normalizeBase64(s), "base64");
    if (buf.length < 2) return null;
    const nodes = parse(buf);
    if (nodes && nodes.length > 0) return nodes;
  } catch {
    /* not base64 protobuf */
  }
  return null;
}

const HEX_CAP = 4096; // cap stored hex per field to bound output size

function readVarint(buf: Buffer, offset: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  let o = offset;
  while (o < buf.length) {
    const byte = buf[o++];
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [result, o];
    shift += 7n;
    if (shift > 70n) return [0n, -1];
  }
  return [0n, -1];
}

function zigzag(n: bigint): bigint {
  return (n >> 1n) ^ -(n & 1n);
}

function isPrintable(buf: Buffer): boolean {
  if (buf.length === 0) return false;
  const text = buf.toString("utf8");
  if (text.includes("�")) return false; // invalid UTF-8
  for (const ch of text) {
    const c = ch.codePointAt(0)!;
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return false;
  }
  return true;
}

/** Detect + decompress common embedded payloads by magic bytes. */
export function tryDecompress(buf: Buffer): { algo: string; data: Buffer } | null {
  if (buf.length < 8) return null;
  try {
    if (buf[0] === 0x1f && buf[1] === 0x8b) return { algo: "gzip", data: zlib.gunzipSync(buf) };
    if (buf[0] === 0x28 && buf[1] === 0xb5 && buf[2] === 0x2f && buf[3] === 0xfd) {
      const z = zlib as unknown as { zstdDecompressSync?: (b: Buffer) => Buffer };
      if (z.zstdDecompressSync) return { algo: "zstd", data: z.zstdDecompressSync(buf) };
    }
    if (buf[0] === 0x78 && (buf[1] === 0x01 || buf[1] === 0x9c || buf[1] === 0xda)) {
      return { algo: "zlib", data: zlib.inflateSync(buf) };
    }
  } catch {
    /* not actually compressed */
  }
  return null;
}

/** Strict parse: returns null if the buffer isn't valid protobuf wire format. */
export function parse(buf: Buffer): PbNode[] | null {
  const nodes: PbNode[] = [];
  let o = 0;
  while (o < buf.length) {
    const [tag, n1] = readVarint(buf, o);
    if (n1 < 0) return null;
    o = n1;
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (field <= 0) return null;

    if (wire === 0) {
      const [v, n] = readVarint(buf, o);
      if (n < 0) return null;
      o = n;
      nodes.push({ field, wire, varint: v.toString(), signed: zigzag(v).toString() });
    } else if (wire === 1) {
      if (o + 8 > buf.length) return null;
      const b = buf.subarray(o, o + 8);
      o += 8;
      nodes.push({
        field,
        wire,
        fixed64: { hex: b.toString("hex"), uint: b.readBigUInt64LE(0).toString(), int: b.readBigInt64LE(0).toString(), double: b.readDoubleLE(0) },
      });
    } else if (wire === 5) {
      if (o + 4 > buf.length) return null;
      const b = buf.subarray(o, o + 4);
      o += 4;
      nodes.push({
        field,
        wire,
        fixed32: { hex: b.toString("hex"), uint: b.readUInt32LE(0), int: b.readInt32LE(0), float: b.readFloatLE(0) },
      });
    } else if (wire === 2) {
      const [len, n] = readVarint(buf, o);
      if (n < 0) return null;
      o = n;
      const L = Number(len);
      if (o + L > buf.length) return null;
      const sub = buf.subarray(o, o + L);
      o += L;
      nodes.push(interpretLD(field, sub));
    } else {
      return null; // groups (3/4) deprecated
    }
  }
  return nodes;
}

function interpretLD(field: number, sub: Buffer): PbNode {
  const node: PbNode = { field, wire: 2, length: sub.length, bytesHex: sub.subarray(0, HEX_CAP).toString("hex") };

  const dz = tryDecompress(sub);
  if (dz) {
    const inner = parse(dz.data);
    node.decompressed = inner && inner.length > 0
      ? { algo: dz.algo, message: inner }
      : isPrintable(dz.data)
        ? { algo: dz.algo, string: dz.data.toString("utf8") }
        : { algo: dz.algo, bytesHex: dz.data.subarray(0, HEX_CAP).toString("hex") };
  }

  const msg = parse(sub);
  if (msg && msg.length > 0) node.message = msg;
  if (isPrintable(sub)) {
    const str = sub.toString("utf8");
    node.string = str;
    // Tokens are often base64url protobuf nested inside a string field.
    if (!node.message) {
      const b64 = tryBase64Protobuf(str);
      if (b64) node.base64Decoded = b64;
    }
  }
  return node;
}

/** Top-level inspect; null if not protobuf. */
export function inspect(buf: Buffer): PbNode[] | null {
  return parse(buf);
}

// --- gRPC framing ---------------------------------------------------------

/** Split a gRPC body ([1B flag][4B length][payload]...) into payload frames. */
export function unframeGrpc(buf: Buffer): Buffer[] | null {
  const frames: Buffer[] = [];
  let o = 0;
  while (o + 5 <= buf.length) {
    const flag = buf[o];
    if (flag !== 0 && flag !== 1) return null;
    const len = buf.readUInt32BE(o + 1);
    o += 5;
    if (o + len > buf.length) return null;
    let payload = buf.subarray(o, o + len);
    o += len;
    if (flag === 1) {
      const dz = tryDecompress(payload);
      if (dz) payload = dz.data;
    }
    frames.push(payload);
  }
  return o === buf.length && frames.length > 0 ? frames : null;
}

// --- Rendering ------------------------------------------------------------

function hexPreview(hex: string): string {
  return hex.length > 96 ? `${hex.slice(0, 96)}... (${hex.length / 2}b)` : `${hex} (${hex.length / 2}b)`;
}

/** Render nodes as indented text, choosing a primary interpretation per field
 *  but annotating alternatives so nothing is hidden. */
export function toText(nodes: PbNode[], indent = 0): string {
  const pad = "  ".repeat(indent);
  const lines: string[] = [];
  for (const n of nodes) {
    if (n.varint !== undefined) {
      lines.push(`${pad}${n.field}: ${n.varint}${n.signed !== n.varint ? ` (zigzag ${n.signed})` : ""}`);
    } else if (n.fixed64) {
      lines.push(`${pad}${n.field}: 0x${n.fixed64.hex} (i64=${n.fixed64.int}, f64=${n.fixed64.double})`);
    } else if (n.fixed32) {
      lines.push(`${pad}${n.field}: 0x${n.fixed32.hex} (i32=${n.fixed32.int}, f32=${n.fixed32.float})`);
    } else {
      // length-delimited
      if (n.decompressed) {
        const d = n.decompressed;
        lines.push(`${pad}${n.field} [${d.algo}] {`);
        if (d.message) lines.push(toText(d.message, indent + 1));
        else if (d.string !== undefined) lines.push(`${pad}  "${d.string}"`);
        else lines.push(`${pad}  bytes ${hexPreview(d.bytesHex ?? "")}`);
        lines.push(`${pad}}`);
      } else if (n.message) {
        const alt = n.string !== undefined ? `  // also text: "${truncate(n.string)}"` : "";
        lines.push(`${pad}${n.field} {${alt}`);
        lines.push(toText(n.message, indent + 1));
        lines.push(`${pad}}`);
      } else if (n.base64Decoded) {
        lines.push(`${pad}${n.field} [base64 protobuf] {  // "${truncate(n.string ?? "")}"`);
        lines.push(toText(n.base64Decoded, indent + 1));
        lines.push(`${pad}}`);
      } else if (n.string !== undefined) {
        lines.push(`${pad}${n.field}: "${n.string}"`);
      } else {
        lines.push(`${pad}${n.field}: bytes ${hexPreview(n.bytesHex ?? "")}`);
      }
    }
  }
  return lines.join("\n");
}

function truncate(s: string, n = 60): string {
  return s.length > n ? s.slice(0, n) + "..." : s;
}

/** Convenience for auto-detection callers: parse + render, or null. */
export function decodeRaw(buf: Buffer): string | null {
  const nodes = parse(buf);
  if (!nodes || nodes.length === 0) return null;
  return toText(nodes);
}

// --- Flatten / diff (for building automations across samples) -------------

/** Flatten to [path, value] pairs keyed by field-number path (e.g. "1.3.2"). */
export function flatten(nodes: PbNode[], prefix = ""): [string, string][] {
  const out: [string, string][] = [];
  const counts = new Map<number, number>();
  for (const n of nodes) {
    const seen = counts.get(n.field) ?? 0;
    counts.set(n.field, seen + 1);
    const path = `${prefix}${n.field}${seen > 0 ? `[${seen}]` : ""}`;
    if (n.message) out.push(...flatten(n.message, path + "."));
    else if (n.decompressed?.message) out.push(...flatten(n.decompressed.message, path + "."));
    else if (n.base64Decoded) out.push(...flatten(n.base64Decoded, path + "."));
    else if (n.varint !== undefined) out.push([path, n.varint]);
    else if (n.fixed64) out.push([path, n.fixed64.int]);
    else if (n.fixed32) out.push([path, String(n.fixed32.int)]);
    else if (n.string !== undefined) out.push([path, JSON.stringify(n.string)]);
    else out.push([path, `bytes:${n.bytesHex?.slice(0, 32) ?? ""}`]);
  }
  return out;
}

export interface PbDiff {
  changed: { path: string; a: string; b: string }[];
  onlyA: { path: string; value: string }[];
  onlyB: { path: string; value: string }[];
}

/** Structural diff of two protobuf messages by field path. */
export function diff(a: PbNode[], b: PbNode[]): PbDiff {
  const ma = new Map(flatten(a));
  const mb = new Map(flatten(b));
  const changed: PbDiff["changed"] = [];
  const onlyA: PbDiff["onlyA"] = [];
  const onlyB: PbDiff["onlyB"] = [];
  for (const [path, va] of ma) {
    if (!mb.has(path)) onlyA.push({ path, value: va });
    else if (mb.get(path) !== va) changed.push({ path, a: va, b: mb.get(path)! });
  }
  for (const [path, vb] of mb) if (!ma.has(path)) onlyB.push({ path, value: vb });
  return { changed, onlyA, onlyB };
}
