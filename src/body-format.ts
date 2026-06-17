import { StoredBody, bodyBuffer, headerValue } from "./traffic-store.js";
import { decodeRaw, unframeGrpc } from "./protobuf.js";

export type BodyFormat = "auto" | "text" | "json" | "hex" | "protobuf" | "base64";

type Headers = Record<string, string | string[] | undefined>;

/** Hex dump with offsets + ASCII gutter, capped to maxBytes. */
function hexDump(buf: Buffer, maxBytes = 4096): string {
  const slice = buf.subarray(0, maxBytes);
  const lines: string[] = [];
  for (let i = 0; i < slice.length; i += 16) {
    const chunk = slice.subarray(i, i + 16);
    const hex = [...chunk].map((b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = [...chunk].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (buf.length > maxBytes) lines.push(`... (${buf.length - maxBytes} more bytes)`);
  return lines.join("\n");
}

function looksLikeProtobuf(contentType: string | undefined): boolean {
  if (!contentType) return false;
  const c = contentType.toLowerCase();
  return c.includes("protobuf") || c.includes("grpc") || c.includes("application/x-protobuf");
}

/**
 * Render a stored body in the requested representation. `auto` picks based on
 * Content-Type, falling back to protobuf/hex for binary payloads.
 */
export function renderBody(body: StoredBody | undefined, headers: Headers, format: BodyFormat): string {
  const buf = bodyBuffer(body);
  if (!buf || buf.length === 0) return "(empty body)";
  const contentType = headerValue(headers, "content-type");
  const trunc = body?.truncated ? `\n(NOTE: body truncated to ${buf.length} of ${body.size} bytes)` : "";

  const asText = () => buf.toString("utf8") + trunc;
  const asJson = () => {
    try {
      return JSON.stringify(JSON.parse(buf.toString("utf8")), null, 2) + trunc;
    } catch {
      return "(not valid JSON)\n" + buf.toString("utf8") + trunc;
    }
  };
  const asProto = () => {
    if ((contentType ?? "").toLowerCase().includes("grpc")) {
      const frames = unframeGrpc(buf);
      if (frames) {
        return frames.map((f, i) => `--- grpc frame ${i} ---\n${decodeRaw(f) ?? hexDump(f)}`).join("\n") + trunc;
      }
    }
    const decoded = decodeRaw(buf);
    return decoded ? decoded + trunc : "(not decodable as protobuf)\n" + hexDump(buf) + trunc;
  };
  const asHex = () => hexDump(buf) + trunc;
  const asBase64 = () => buf.toString("base64");

  switch (format) {
    case "text":
      return asText();
    case "json":
      return asJson();
    case "protobuf":
      return asProto();
    case "hex":
      return asHex();
    case "base64":
      return asBase64();
    case "auto":
    default: {
      const c = (contentType ?? "").toLowerCase();
      if (c.includes("json")) return asJson();
      if (looksLikeProtobuf(contentType)) return asProto();
      if (c.startsWith("text/") || c.includes("xml") || c.includes("html") || c.includes("urlencoded")) {
        return asText();
      }
      // Unknown binary: try protobuf, then printable text, else hex.
      const proto = decodeRaw(buf);
      if (proto) return `(auto-detected protobuf)\n${proto}${trunc}`;
      const text = buf.toString("utf8");
      if (!text.includes("�")) return text + trunc;
      return asHex();
    }
  }
}

export interface ParsedCookie {
  name: string;
  value: string;
  attributes?: Record<string, string | boolean>;
}

/** Parse request cookies from the Cookie header. */
export function parseRequestCookies(headers: Headers): ParsedCookie[] {
  const raw = headerValue(headers, "cookie");
  if (!raw) return [];
  return raw
    .split(";")
    .map((p) => p.trim())
    .filter(Boolean)
    .map((pair) => {
      const eq = pair.indexOf("=");
      return eq === -1
        ? { name: pair, value: "" }
        : { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
    });
}

/** Parse response cookies from all Set-Cookie headers (with attributes). */
export function parseResponseCookies(headers: Headers): ParsedCookie[] {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === "set-cookie");
  if (!key) return [];
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return list.map((line) => {
    const parts = line.split(";").map((p) => p.trim());
    const [nameVal, ...attrParts] = parts;
    const eq = nameVal.indexOf("=");
    const name = eq === -1 ? nameVal : nameVal.slice(0, eq);
    const value = eq === -1 ? "" : nameVal.slice(eq + 1);
    const attributes: Record<string, string | boolean> = {};
    for (const a of attrParts) {
      const ae = a.indexOf("=");
      if (ae === -1) attributes[a.toLowerCase()] = true;
      else attributes[a.slice(0, ae).toLowerCase()] = a.slice(ae + 1);
    }
    return { name, value, attributes: attrParts.length ? attributes : undefined };
  });
}
