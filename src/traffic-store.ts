/**
 * In-memory ring buffer of captured HTTP(S) exchanges.
 * Requests and responses are correlated by Mockttp's request id.
 * Bodies are stored as decoded (decompressed) bytes so we can render them
 * later as text / json / hex / protobuf on demand.
 */

export interface StoredBody {
  /** Decoded (decompressed) bytes, base64-encoded; may be truncated. */
  base64: string;
  /** Full original byte length before any truncation. */
  size: number;
  truncated: boolean;
}

export interface WsMessage {
  direction: "sent" | "received";
  timestamp: number;
  isBinary: boolean;
  body: StoredBody;
}

export interface Exchange {
  id: string;
  timestamp: number;
  method: string;
  url: string;
  protocol: string;
  host: string;
  path: string;
  requestHeaders: Record<string, string | string[] | undefined>;
  requestBody?: StoredBody;
  // Response side (filled in when the response event arrives)
  statusCode?: number;
  statusMessage?: string;
  responseHeaders?: Record<string, string | string[] | undefined>;
  responseBody?: StoredBody;
  responseTimestamp?: number;
  durationMs?: number;
  aborted?: boolean;
  // WebSocket side
  isWebSocket?: boolean;
  wsMessages?: WsMessage[];
  wsClose?: { code?: number; reason: string };
}

export interface TrafficFilter {
  host?: string;
  method?: string;
  urlPattern?: string;
  status?: number;
  minStatus?: number;
  limit?: number;
  search?: string; // matches against url, headers and bodies
}

export function bodyText(body: StoredBody | undefined): string | undefined {
  if (!body) return undefined;
  return Buffer.from(body.base64, "base64").toString("utf8");
}

export function bodyBuffer(body: StoredBody | undefined): Buffer | undefined {
  if (!body) return undefined;
  return Buffer.from(body.base64, "base64");
}

export class TrafficStore {
  private items = new Map<string, Exchange>();
  private order: string[] = [];

  constructor(
    private readonly maxItems = 2000,
    readonly maxBody = 500_000,
  ) {}

  addRequest(ex: Exchange): void {
    this.items.set(ex.id, ex);
    this.order.push(ex.id);
    while (this.order.length > this.maxItems) {
      const evicted = this.order.shift()!;
      this.items.delete(evicted);
    }
  }

  addResponse(id: string, patch: Partial<Exchange>): void {
    const ex = this.items.get(id);
    if (!ex) return;
    Object.assign(ex, patch);
    if (ex.responseTimestamp) ex.durationMs = ex.responseTimestamp - ex.timestamp;
  }

  markAborted(id: string): void {
    const ex = this.items.get(id);
    if (ex) ex.aborted = true;
  }

  addWsMessage(streamId: string, msg: WsMessage): void {
    const ex = this.items.get(streamId);
    if (!ex) return;
    (ex.wsMessages ??= []).push(msg);
  }

  setWsClose(streamId: string, code: number | undefined, reason: string): void {
    const ex = this.items.get(streamId);
    if (ex) ex.wsClose = { code, reason };
  }

  get(id: string): Exchange | undefined {
    return this.items.get(id);
  }

  clear(): number {
    const n = this.order.length;
    this.items.clear();
    this.order = [];
    return n;
  }

  count(): number {
    return this.order.length;
  }

  /** Load exchanges from a parsed HAR 1.2 object. Returns the count imported. */
  importHar(har: any): number {
    const entries = har?.log?.entries;
    if (!Array.isArray(entries)) throw new Error("Not a HAR archive (missing log.entries).");
    let imported = 0;
    for (const e of entries) {
      const req = e.request ?? {};
      const res = e.response ?? {};
      let url: URL | undefined;
      try {
        url = new URL(req.url);
      } catch {
        /* keep undefined */
      }
      const ex: Exchange = {
        id: `har-${++this.importSeq}`,
        timestamp: e.startedDateTime ? Date.parse(e.startedDateTime) : Date.now(),
        method: req.method ?? "GET",
        url: req.url ?? "",
        protocol: url?.protocol.replace(":", "") ?? "",
        host: url?.host ?? "",
        path: url ? url.pathname + url.search : "",
        requestHeaders: harHeaders(req.headers),
        requestBody: harBody(req.postData?.text, false),
        statusCode: res.status,
        statusMessage: res.statusText,
        responseHeaders: harHeaders(res.headers),
        responseBody: harBody(res.content?.text, res.content?.encoding === "base64"),
        durationMs: typeof e.time === "number" ? Math.round(e.time) : undefined,
      };
      this.addRequest(ex);
      imported++;
    }
    return imported;
  }

  private importSeq = 0;

  list(filter: TrafficFilter = {}): Exchange[] {
    const urlRe = filter.urlPattern ? safeRegExp(filter.urlPattern) : undefined;
    const search = filter.search?.toLowerCase();
    const out: Exchange[] = [];
    for (let i = this.order.length - 1; i >= 0; i--) {
      const ex = this.items.get(this.order[i])!;
      if (filter.host && ex.host !== filter.host) continue;
      if (filter.method && ex.method.toUpperCase() !== filter.method.toUpperCase()) continue;
      if (urlRe && !urlRe.test(ex.url)) continue;
      if (filter.status !== undefined && ex.statusCode !== filter.status) continue;
      if (filter.minStatus !== undefined && (ex.statusCode ?? 0) < filter.minStatus) continue;
      if (search && !matchesSearch(ex, search)) continue;
      out.push(ex);
      if (filter.limit && out.length >= filter.limit) break;
    }
    return out;
  }

  /** Build a minimal HAR 1.2 archive from the (optionally filtered) exchanges. */
  toHar(filter: TrafficFilter = {}): unknown {
    const entries = this.list(filter).reverse().map((ex) => {
      const reqText = bodyText(ex.requestBody);
      const resText = bodyText(ex.responseBody);
      return {
        startedDateTime: new Date(ex.timestamp).toISOString(),
        time: ex.durationMs ?? 0,
        request: {
          method: ex.method,
          url: ex.url,
          httpVersion: "HTTP/1.1",
          headers: headersToHar(ex.requestHeaders),
          queryString: queryToHar(ex.url),
          headersSize: -1,
          bodySize: ex.requestBody?.size ?? 0,
          postData: reqText
            ? { mimeType: headerValue(ex.requestHeaders, "content-type") ?? "", text: reqText }
            : undefined,
        },
        response: {
          status: ex.statusCode ?? 0,
          statusText: ex.statusMessage ?? "",
          httpVersion: "HTTP/1.1",
          headers: headersToHar(ex.responseHeaders ?? {}),
          content: {
            size: ex.responseBody?.size ?? 0,
            mimeType: headerValue(ex.responseHeaders ?? {}, "content-type") ?? "",
            text: resText,
          },
          redirectURL: headerValue(ex.responseHeaders ?? {}, "location") ?? "",
          headersSize: -1,
          bodySize: ex.responseBody?.size ?? 0,
        },
        cache: {},
        timings: { send: 0, wait: ex.durationMs ?? 0, receive: 0 },
      };
    });

    return {
      log: { version: "1.2", creator: { name: "httptoolkit-mcp", version: "0.1.0" }, entries },
    };
  }
}

function matchesSearch(ex: Exchange, q: string): boolean {
  if (ex.url.toLowerCase().includes(q)) return true;
  if (bodyText(ex.requestBody)?.toLowerCase().includes(q)) return true;
  if (bodyText(ex.responseBody)?.toLowerCase().includes(q)) return true;
  if (JSON.stringify(ex.requestHeaders).toLowerCase().includes(q)) return true;
  if (ex.responseHeaders && JSON.stringify(ex.responseHeaders).toLowerCase().includes(q)) return true;
  return false;
}

function safeRegExp(pattern: string): RegExp | undefined {
  try {
    return new RegExp(pattern, "i");
  } catch {
    return undefined;
  }
}

export function headerValue(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  if (!key) return undefined;
  const v = headers[key];
  return Array.isArray(v) ? v.join(", ") : v;
}

function headersToHar(headers: Record<string, string | string[] | undefined>) {
  const out: { name: string; value: string }[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) value.forEach((v) => out.push({ name, value: v }));
    else out.push({ name, value });
  }
  return out;
}

function harHeaders(list: unknown): Record<string, string | string[] | undefined> {
  const out: Record<string, string | string[] | undefined> = {};
  if (!Array.isArray(list)) return out;
  for (const h of list as { name: string; value: string }[]) {
    if (!h?.name) continue;
    const existing = out[h.name];
    if (existing === undefined) out[h.name] = h.value;
    else if (Array.isArray(existing)) existing.push(h.value);
    else out[h.name] = [existing, h.value];
  }
  return out;
}

function harBody(text: string | undefined, isBase64: boolean): StoredBody | undefined {
  if (!text) return undefined;
  const buf = isBase64 ? Buffer.from(text, "base64") : Buffer.from(text, "utf8");
  if (buf.length === 0) return undefined;
  return { base64: buf.toString("base64"), size: buf.length, truncated: false };
}

function queryToHar(url: string) {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}
