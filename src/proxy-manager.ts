import { promises as fs } from "node:fs";
import path from "node:path";
import {
  getLocal,
  generateCACertificate,
  Mockttp,
  CompletedRequest,
  CompletedResponse,
  AbortedRequest,
  WebSocketMessage,
  WebSocketClose,
} from "mockttp";
import { TrafficStore, Exchange, StoredBody } from "./traffic-store.js";

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;

export interface RuleMatch {
  /** Restrict to a single HTTP method. Omit to match all methods. */
  method?: string;
  /** JS RegExp source matched (case-insensitive) against the full request URL. */
  urlPattern?: string;
}

export type RuleAction =
  | { type: "mock"; status: number; body?: string; headers?: Record<string, string>; json?: unknown }
  | { type: "error"; kind: "reset" | "timeout" | "close" }
  | { type: "delay"; ms: number }
  | { type: "redirect"; toUrl: string }
  | {
      type: "modify-request";
      setHeaders?: Record<string, string>;
      removeHeaders?: string[];
      replaceBody?: string;
    };

export interface Rule {
  id: string;
  match: RuleMatch;
  action: RuleAction;
}

export interface ProxyStatus {
  running: boolean;
  port?: number;
  host?: string;
  capturedCount: number;
  ruleCount: number;
}

export class ProxyManager {
  private server: Mockttp | undefined;
  private ca: { key: string; cert: string } | undefined;
  private rules: Rule[] = [];
  private port: number | undefined;
  private ruleSeq = 0;

  constructor(
    private readonly store: TrafficStore,
    private readonly certDir: string,
  ) {}

  get running(): boolean {
    return this.server !== undefined;
  }

  /** Load a persisted CA from disk, or generate and persist a fresh one. */
  async ensureCa(): Promise<{ key: string; cert: string }> {
    if (this.ca) return this.ca;
    const certPath = path.join(this.certDir, "ca.pem");
    const keyPath = path.join(this.certDir, "ca.key");
    try {
      const [cert, key] = await Promise.all([
        fs.readFile(certPath, "utf8"),
        fs.readFile(keyPath, "utf8"),
      ]);
      this.ca = { cert, key };
    } catch {
      await fs.mkdir(this.certDir, { recursive: true });
      const generated = await generateCACertificate({ commonName: "HTTPToolkit MCP CA" });
      await Promise.all([
        fs.writeFile(certPath, generated.cert),
        fs.writeFile(keyPath, generated.key),
      ]);
      this.ca = { cert: generated.cert, key: generated.key };
    }
    return this.ca;
  }

  async getCaPem(): Promise<string> {
    return (await this.ensureCa()).cert;
  }

  get caPath(): string {
    return path.join(this.certDir, "ca.pem");
  }

  async start(port = 8000): Promise<ProxyStatus> {
    if (this.server) return this.status();
    const ca = await this.ensureCa();
    this.server = getLocal({
      https: { key: ca.key, cert: ca.cert },
      recordTraffic: false,
    });
    await this.server.start(port);
    this.port = port;
    await this.rebuild();
    return this.status();
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await this.server.stop();
    this.server = undefined;
    this.port = undefined;
  }

  status(): ProxyStatus {
    return {
      running: this.running,
      port: this.port,
      host: this.server?.url,
      capturedCount: this.store.count(),
      ruleCount: this.rules.length,
    };
  }

  // --- Rules -------------------------------------------------------------

  listRules(): Rule[] {
    return [...this.rules];
  }

  async addRule(match: RuleMatch, action: RuleAction): Promise<Rule> {
    const rule: Rule = { id: `r${++this.ruleSeq}`, match, action };
    this.rules.push(rule);
    if (this.server) await this.rebuild();
    return rule;
  }

  async removeRule(id: string): Promise<boolean> {
    const before = this.rules.length;
    this.rules = this.rules.filter((r) => r.id !== id);
    const removed = this.rules.length < before;
    if (removed && this.server) await this.rebuild();
    return removed;
  }

  async clearRules(): Promise<void> {
    this.rules = [];
    if (this.server) await this.rebuild();
  }

  /**
   * Reset the server and re-apply all rules. Mockttp's reset() also removes
   * every event listener, so we re-subscribe capture handlers at the end.
   */
  private async rebuild(): Promise<void> {
    const server = this.server;
    if (!server) return;
    await server.reset();

    for (const rule of this.rules) {
      await this.applyRule(server, rule);
    }
    // Fallback: forward everything else untouched so apps keep working.
    await server.forUnmatchedRequest().thenPassThrough();
    await server.forAnyWebSocket().thenPassThrough();

    server.on("request", this.onRequest);
    server.on("response", this.onResponse);
    server.on("abort", this.onAbort);
    server.on("websocket-request", this.onWsRequest);
    server.on("websocket-accepted", this.onWsAccepted);
    server.on("websocket-message-received", this.onWsMessage);
    server.on("websocket-message-sent", this.onWsMessage);
    server.on("websocket-close", this.onWsClose);
  }

  private async applyRule(server: Mockttp, rule: Rule): Promise<void> {
    const methods = rule.match.method ? [rule.match.method.toUpperCase()] : [...HTTP_METHODS];
    const urlMatcher = rule.match.urlPattern ? new RegExp(rule.match.urlPattern, "i") : undefined;
    for (const method of methods) {
      const builder = this.builderFor(server, method, urlMatcher);
      if (!builder) continue;
      await this.attachAction(builder, rule.action);
    }
  }

  private builderFor(server: Mockttp, method: string, urlMatcher: RegExp | undefined) {
    const fnName = "for" + method.charAt(0) + method.slice(1).toLowerCase();
    const fn = (server as unknown as Record<string, (m?: unknown) => unknown>)[fnName];
    if (typeof fn !== "function") return undefined;
    return urlMatcher ? fn.call(server, urlMatcher) : fn.call(server);
  }

  private async attachAction(builder: any, action: RuleAction): Promise<void> {
    switch (action.type) {
      case "mock":
        if (action.json !== undefined) {
          await builder.thenJson(action.status, action.json, action.headers ?? {});
        } else {
          await builder.thenReply(action.status, action.body ?? "", action.headers ?? {});
        }
        return;
      case "error":
        if (action.kind === "reset") await builder.thenResetConnection();
        else if (action.kind === "timeout") await builder.thenTimeout();
        else await builder.thenCloseConnection();
        return;
      case "delay":
        await builder.thenPassThrough({
          beforeRequest: async () => {
            await new Promise((r) => setTimeout(r, action.ms));
          },
        });
        return;
      case "redirect":
        await builder.thenPassThrough({
          beforeRequest: () => ({ url: action.toUrl }),
        });
        return;
      case "modify-request":
        await builder.thenPassThrough({
          beforeRequest: (req: CompletedRequest) => {
            const headers = { ...req.headers } as Record<string, string | string[] | undefined>;
            for (const [k, v] of Object.entries(action.setHeaders ?? {})) headers[k] = v;
            for (const k of action.removeHeaders ?? []) delete headers[k];
            return {
              headers: headers as Record<string, string>,
              ...(action.replaceBody !== undefined ? { body: action.replaceBody } : {}),
            };
          },
        });
        return;
    }
  }

  // --- Capture handlers --------------------------------------------------

  private onRequest = async (req: CompletedRequest): Promise<void> => {
    let url: URL | undefined;
    try {
      url = new URL(req.url);
    } catch {
      /* keep undefined */
    }
    const ex: Exchange = {
      id: req.id,
      timestamp: Date.now(),
      method: req.method,
      url: req.url,
      protocol: url?.protocol.replace(":", "") ?? "",
      host: url?.host ?? req.headers["host"]?.toString() ?? "",
      path: url ? url.pathname + url.search : req.path,
      requestHeaders: req.headers,
      requestBody: await readBody(req.body, this.store.maxBody),
    };
    this.store.addRequest(ex);
  };

  private onResponse = async (res: CompletedResponse): Promise<void> => {
    this.store.addResponse(res.id, {
      statusCode: res.statusCode,
      statusMessage: res.statusMessage,
      responseHeaders: res.headers,
      responseBody: await readBody(res.body, this.store.maxBody),
      responseTimestamp: Date.now(),
    });
  };

  private onAbort = (req: AbortedRequest): void => {
    this.store.markAborted(req.id);
  };

  private onWsRequest = async (req: CompletedRequest): Promise<void> => {
    let url: URL | undefined;
    try {
      url = new URL(req.url);
    } catch {
      /* keep undefined */
    }
    this.store.addRequest({
      id: req.id,
      timestamp: Date.now(),
      method: req.method,
      url: req.url,
      protocol: url?.protocol.replace(":", "") ?? "",
      host: url?.host ?? req.headers["host"]?.toString() ?? "",
      path: url ? url.pathname + url.search : req.path,
      requestHeaders: req.headers,
      requestBody: await readBody(req.body, this.store.maxBody),
      isWebSocket: true,
      statusMessage: "WebSocket",
    });
  };

  private onWsAccepted = (res: CompletedResponse): void => {
    this.store.addResponse(res.id, {
      statusCode: res.statusCode,
      statusMessage: res.statusMessage,
      responseHeaders: res.headers,
      responseTimestamp: Date.now(),
    });
  };

  private onWsMessage = (msg: WebSocketMessage): void => {
    const buf = Buffer.from(msg.content);
    const truncated = buf.length > this.store.maxBody;
    const stored = truncated ? buf.subarray(0, this.store.maxBody) : buf;
    this.store.addWsMessage(msg.streamId, {
      direction: msg.direction,
      timestamp: Date.now(),
      isBinary: msg.isBinary,
      body: { base64: stored.toString("base64"), size: buf.length, truncated },
    });
  };

  private onWsClose = (c: WebSocketClose): void => {
    this.store.setWsClose(c.streamId, c.closeCode, c.closeReason);
  };
}

interface MockttpBody {
  getDecodedBuffer(): Promise<Buffer | undefined>;
}

async function readBody(
  body: MockttpBody | undefined,
  maxBody: number,
): Promise<StoredBody | undefined> {
  if (!body) return undefined;
  try {
    const buf = await body.getDecodedBuffer();
    if (!buf || buf.length === 0) return undefined;
    const truncated = buf.length > maxBody;
    const stored = truncated ? buf.subarray(0, maxBody) : buf;
    return { base64: stored.toString("base64"), size: buf.length, truncated };
  } catch {
    return undefined;
  }
}
