/**
 * Blob classifier: given unknown bytes, report what they most likely are so an
 * agent doesn't waste time protobuf-decoding ciphertext. Uses Shannon entropy,
 * magic bytes, and structural parse attempts (JSON / protobuf / base64 / gRPC).
 */
import { parse as pbParse, normalizeBase64, unframeGrpc } from "./protobuf.js";

export interface ClassifyContext {
  host?: string;
  isWebSocket?: boolean;
  contentType?: string;
}

/** Shannon entropy in bits/byte (0 = constant, 8 = uniformly random). */
export function entropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (const b of buf) counts[b]++;
  let h = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function printableRatio(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let printable = 0;
  for (const b of buf) {
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
  }
  return printable / buf.length;
}

function magic(buf: Buffer): string | null {
  const b = buf;
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) return "gzip";
  if (b.length >= 4 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd) return "zstd";
  if (b.length >= 2 && b[0] === 0x78 && [0x01, 0x9c, 0xda].includes(b[1])) return "zlib/deflate";
  if (b.length >= 3 && b[0] === 0x16 && b[1] === 0x03 && b[2] <= 0x04) return "TLS handshake record";
  if (b.length >= 3 && b[0] === 0x17 && b[1] === 0x03) return "TLS application-data record";
  if (b.length >= 4 && b.toString("ascii", 0, 4) === "%PDF") return "PDF";
  if (b.length >= 2 && b[0] === 0x50 && b[1] === 0x4b) return "ZIP/JAR/APK";
  if (b.length >= 8 && b[0] === 0x89 && b.toString("ascii", 1, 4) === "PNG") return "PNG";
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "JPEG";
  return null;
}

function looksBase64(s: string): boolean {
  return s.length >= 16 && /^[A-Za-z0-9_\-+/]+=*$/.test(s.trim());
}

/** Produce a human-readable classification report. */
export function classify(buf: Buffer, ctx: ClassifyContext = {}): string {
  const lines: string[] = [];
  const ent = entropy(buf);
  const printable = printableRatio(buf);
  lines.push(`size: ${buf.length} bytes`);
  lines.push(`entropy: ${ent.toFixed(2)} bits/byte`);
  lines.push(`printable: ${(printable * 100).toFixed(0)}%`);

  const m = magic(buf);
  if (m) lines.push(`magic: ${m}`);

  const verdicts: string[] = [];

  // Structured-format attempts.
  const text = buf.toString("utf8");
  let isJson = false;
  if (printable > 0.95) {
    try {
      JSON.parse(text);
      isJson = true;
      verdicts.push("JSON (valid) - read as text/json");
    } catch {
      /* not json */
    }
  }

  if (!isJson && pbParse(buf)) verdicts.push("parses as protobuf - use decode_protobuf");
  if (unframeGrpc(buf)) verdicts.push("gRPC framing detected - decode_protobuf with grpc=true");

  if (m === "gzip" || m === "zstd" || m === "zlib/deflate") {
    verdicts.push(`compressed (${m}) - decode_protobuf auto-decompresses, or get_body hex`);
  }

  // base64(url) wrapper?
  if (!isJson && looksBase64(text.trim())) {
    try {
      const inner = Buffer.from(normalizeBase64(text.trim()), "base64");
      if (inner.length > 1) {
        const innerKind = pbParse(inner) ? "protobuf" : magic(inner) ?? (printableRatio(inner) > 0.9 ? "text" : `binary (entropy ${entropy(inner).toFixed(2)})`);
        verdicts.push(`base64(url) wrapper -> inner looks like ${innerKind}`);
      }
    } catch {
      /* not base64 */
    }
  }

  // Encryption / opaqueness heuristic.
  const host = ctx.host?.toLowerCase() ?? "";
  const isWhatsApp = /whatsapp\.net|whatsapp\.com|wa\.me/.test(host);
  if (ent > 7.5 && !m) {
    verdicts.push(
      "HIGH ENTROPY with no structure - almost certainly ENCRYPTED or already-compressed ciphertext. Not decodable by passive MITM.",
    );
  }
  if (isWhatsApp || (ctx.isWebSocket && ent > 7.0)) {
    verdicts.push(
      "Looks like an encrypted transport (e.g. WhatsApp Noise / E2E). Passive sniffing yields ciphertext only - decoding needs the session keys (act as a client, Baileys-style), not a proxy.",
    );
  }

  if (verdicts.length === 0) {
    verdicts.push(
      printable > 0.85 ? "mostly text but no known structure" : "unknown binary with no recognizable structure",
    );
  }

  lines.push("", "verdict:");
  for (const v of verdicts) lines.push(`  - ${v}`);
  return lines.join("\n");
}
