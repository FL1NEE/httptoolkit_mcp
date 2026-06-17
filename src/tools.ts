import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ProxyManager, RuleMatch } from "./proxy-manager.js";
import { TrafficStore, Exchange, bodyBuffer } from "./traffic-store.js";
import { Adb, EMULATOR_PRESETS } from "./adb.js";
import { renderBody, parseRequestCookies, parseResponseCookies } from "./body-format.js";
import { inspect, toText, unframeGrpc, parse as pbParse, diff as pbDiff, normalizeBase64 } from "./protobuf.js";
import { classify } from "./classify.js";
import { headerValue } from "./traffic-store.js";

const BODY_FORMATS = ["auto", "text", "json", "hex", "protobuf", "base64"] as const;

function text(s: string) {
  return { content: [{ type: "text" as const, text: s }] };
}

function localIPv4s(): string[] {
  const out: string[] = [];
  for (const addrs of Object.values(os.networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === "IPv4" && !a.internal) out.push(a.address);
    }
  }
  return out;
}

const matchShape = {
  method: z.string().optional().describe("HTTP method to match (GET, POST, ...). Omit = all methods."),
  urlPattern: z
    .string()
    .optional()
    .describe("RegExp source matched case-insensitively against the full request URL."),
};

function summarizeExchange(ex: Exchange): string {
  const status = ex.aborted ? "ABORTED" : ex.statusCode ?? "...";
  const dur = ex.durationMs !== undefined ? ` ${ex.durationMs}ms` : "";
  const ws = ex.isWebSocket ? ` WS(${ex.wsMessages?.length ?? 0} msgs)` : "";
  return `[${ex.id}] ${ex.method} ${status} ${ex.host}${ex.path}${dur}${ws}`;
}

function dumpHeaders(h: Record<string, string | string[] | undefined>): string {
  return Object.entries(h)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `  ${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
    .join("\n");
}

export function registerTools(
  server: McpServer,
  proxy: ProxyManager,
  store: TrafficStore,
  adb: Adb,
): void {
  // ---- Proxy lifecycle --------------------------------------------------

  server.registerTool(
    "proxy_start",
    {
      title: "Start interception proxy",
      description:
        "Start the Mockttp HTTPS interception proxy. Generates/loads a stable CA. " +
        "Point your emulator's proxy at <host-ip>:<port> and install the CA to capture traffic.",
      inputSchema: { port: z.number().int().min(1).max(65535).optional().describe("Default 8000.") },
    },
    async ({ port }) => {
      const status = await proxy.start(port ?? 8000);
      const ips = localIPv4s();
      return text(
        `Proxy running on port ${status.port}.\n` +
          `Reachable host IPs (use one as the emulator proxy host): ${ips.join(", ") || "n/a"}\n` +
          `CA certificate: ${proxy.caPath}\n` +
          `Next: install the CA on the device and set its proxy (see adb_setup).`,
      );
    },
  );

  server.registerTool(
    "proxy_stop",
    { title: "Stop proxy", description: "Stop the interception proxy.", inputSchema: {} },
    async () => {
      await proxy.stop();
      return text("Proxy stopped.");
    },
  );

  server.registerTool(
    "proxy_status",
    { title: "Proxy status", description: "Report proxy state, captured count and local IPs.", inputSchema: {} },
    async () => {
      const s = proxy.status();
      return text(
        `running: ${s.running}\nport: ${s.port ?? "-"}\ncaptured: ${s.capturedCount}\n` +
          `rules: ${s.ruleCount}\nlocal IPs: ${localIPv4s().join(", ") || "n/a"}`,
      );
    },
  );

  server.registerTool(
    "get_ca_certificate",
    {
      title: "Get CA certificate",
      description: "Return the proxy CA certificate (PEM) and its file path for device installation.",
      inputSchema: {},
    },
    async () => {
      const pem = await proxy.getCaPem();
      return text(`Path: ${proxy.caPath}\n\n${pem}`);
    },
  );

  // ---- Traffic ----------------------------------------------------------

  server.registerTool(
    "list_traffic",
    {
      title: "List captured traffic",
      description: "List captured exchanges (newest first) with optional filters.",
      inputSchema: {
        host: z.string().optional(),
        method: z.string().optional(),
        urlPattern: z.string().optional().describe("RegExp matched against the URL."),
        status: z.number().int().optional(),
        minStatus: z.number().int().optional().describe("e.g. 400 to show only errors."),
        limit: z.number().int().min(1).max(500).optional().describe("Default 50."),
      },
    },
    async (args) => {
      const list = store.list({ ...args, limit: args.limit ?? 50 });
      if (list.length === 0) return text("No matching traffic.");
      return text(`${list.length} exchange(s):\n` + list.map(summarizeExchange).join("\n"));
    },
  );

  server.registerTool(
    "search_traffic",
    {
      title: "Search traffic",
      description: "Full-text search across URLs, headers and bodies of captured exchanges.",
      inputSchema: {
        query: z.string().describe("Case-insensitive substring."),
        limit: z.number().int().min(1).max(200).optional().describe("Default 50."),
      },
    },
    async ({ query, limit }) => {
      const list = store.list({ search: query, limit: limit ?? 50 });
      if (list.length === 0) return text("No matches.");
      return text(`${list.length} match(es):\n` + list.map(summarizeExchange).join("\n"));
    },
  );

  server.registerTool(
    "get_exchange",
    {
      title: "Get exchange detail",
      description:
        "Full detail for one exchange: request line, request/response headers, request & response " +
        "cookies, and both bodies. Bodies render per `bodyFormat` (auto/text/json/hex/protobuf/base64).",
      inputSchema: {
        id: z.string(),
        bodyFormat: z.enum(BODY_FORMATS).optional().describe("How to render bodies. Default auto."),
      },
    },
    async ({ id, bodyFormat }) => {
      const ex = store.get(id);
      if (!ex) return text(`No exchange with id ${id}.`);
      const fmt = bodyFormat ?? "auto";
      const reqCookies = parseRequestCookies(ex.requestHeaders);
      const resCookies = ex.responseHeaders ? parseResponseCookies(ex.responseHeaders) : [];
      const parts = [
        `${ex.method} ${ex.url}`,
        `host: ${ex.host}`,
        ex.aborted ? "ABORTED" : `status: ${ex.statusCode ?? "-"} ${ex.statusMessage ?? ""}`,
        ex.durationMs !== undefined ? `duration: ${ex.durationMs}ms` : "",
        "",
        "--- request headers ---",
        dumpHeaders(ex.requestHeaders),
      ];
      if (reqCookies.length)
        parts.push("", "--- request cookies ---", reqCookies.map((c) => `  ${c.name} = ${c.value}`).join("\n"));
      parts.push("", `--- request body (${fmt}) ---`, renderBody(ex.requestBody, ex.requestHeaders, fmt));
      if (ex.responseHeaders) parts.push("", "--- response headers ---", dumpHeaders(ex.responseHeaders));
      if (resCookies.length)
        parts.push(
          "",
          "--- response cookies (Set-Cookie) ---",
          resCookies
            .map((c) => `  ${c.name} = ${c.value}${c.attributes ? "  " + JSON.stringify(c.attributes) : ""}`)
            .join("\n"),
        );
      parts.push(
        "",
        `--- response body (${fmt}) ---`,
        renderBody(ex.responseBody, ex.responseHeaders ?? {}, fmt),
      );
      if (ex.isWebSocket) {
        parts.push("", `--- websocket messages (${ex.wsMessages?.length ?? 0}) ---`);
        for (const m of ex.wsMessages ?? []) {
          const arrow = m.direction === "sent" ? "->" : "<-";
          parts.push(`${arrow} ${m.isBinary ? "[bin]" : "[text]"} ${renderBody(m.body, {}, fmt)}`);
        }
        if (ex.wsClose) parts.push(`-- closed: code=${ex.wsClose.code ?? "-"} reason="${ex.wsClose.reason}"`);
      }
      return text(parts.filter((p) => p !== "").join("\n"));
    },
  );

  server.registerTool(
    "get_ws_messages",
    {
      title: "Get WebSocket messages",
      description: "List a WebSocket exchange's messages, rendered in the chosen format.",
      inputSchema: {
        id: z.string(),
        format: z.enum(BODY_FORMATS).optional().describe("Default auto."),
        direction: z.enum(["sent", "received", "both"]).optional(),
      },
    },
    async ({ id, format, direction }) => {
      const ex = store.get(id);
      if (!ex) return text(`No exchange with id ${id}.`);
      if (!ex.isWebSocket) return text(`Exchange ${id} is not a WebSocket.`);
      const fmt = format ?? "auto";
      const dir = direction ?? "both";
      const msgs = (ex.wsMessages ?? []).filter((m) => dir === "both" || m.direction === dir);
      if (msgs.length === 0) return text("No messages.");
      return text(
        msgs
          .map((m, i) => {
            const arrow = m.direction === "sent" ? "->" : "<-";
            return `#${i} ${arrow} ${m.isBinary ? "[bin]" : "[text]"}\n${renderBody(m.body, {}, fmt)}`;
          })
          .join("\n\n"),
      );
    },
  );

  server.registerTool(
    "get_body",
    {
      title: "Get one body",
      description: "Return just the request or response body of an exchange in a chosen format.",
      inputSchema: {
        id: z.string(),
        side: z.enum(["request", "response"]),
        format: z.enum(BODY_FORMATS).optional().describe("Default auto."),
      },
    },
    async ({ id, side, format }) => {
      const ex = store.get(id);
      if (!ex) return text(`No exchange with id ${id}.`);
      const body = side === "request" ? ex.requestBody : ex.responseBody;
      const headers = side === "request" ? ex.requestHeaders : ex.responseHeaders ?? {};
      return text(renderBody(body, headers, format ?? "auto"));
    },
  );

  // ---- Protobuf reverse-engineering -------------------------------------

  const resolveBuffer = (
    args: { id?: string; side?: "request" | "response"; hex?: string; base64?: string },
  ): Buffer | undefined => {
    if (args.hex) return Buffer.from(args.hex.replace(/\s+/g, ""), "hex");
    if (args.base64) return Buffer.from(normalizeBase64(args.base64), "base64");
    if (args.id) {
      const ex = store.get(args.id);
      if (!ex) return undefined;
      return bodyBuffer(args.side === "request" ? ex.requestBody : ex.responseBody);
    }
    return undefined;
  };

  server.registerTool(
    "decode_protobuf",
    {
      title: "Decode protobuf (deep)",
      description:
        "Schema-less protobuf decode that keeps ALL interpretations per field (message/string/bytes) " +
        "and transparently decompresses embedded gzip/zlib/zstd and unwraps gRPC frames. Input a " +
        "captured exchange body, or paste raw hex/base64. Use output=json to get a structured tree " +
        "for building automations.",
      inputSchema: {
        id: z.string().optional().describe("Exchange id (with `side`)."),
        side: z.enum(["request", "response"]).optional(),
        hex: z.string().optional().describe("Raw bytes as hex."),
        base64: z.string().optional().describe("Raw bytes as base64 or base64url (e.g. a YouTube token)."),
        grpc: z.boolean().optional().describe("Force gRPC frame unwrapping."),
        output: z.enum(["text", "json"]).optional().describe("Default text."),
      },
    },
    async (args) => {
      const buf = resolveBuffer(args);
      if (!buf || buf.length === 0) return text("No bytes to decode (check id/side/hex/base64).");
      const frames = args.grpc ? unframeGrpc(buf) : null;
      const buffers = frames ?? [buf];
      const out = buffers.map((b, i) => {
        const nodes = inspect(b);
        const header = frames ? `--- frame ${i} ---\n` : "";
        if (!nodes) return header + "(not valid protobuf)";
        return header + (args.output === "json" ? JSON.stringify(nodes, null, 2) : toText(nodes));
      });
      return text(out.join("\n\n"));
    },
  );

  server.registerTool(
    "classify_blob",
    {
      title: "Classify unknown bytes",
      description:
        "Tell what an unknown blob most likely is (entropy + magic bytes + JSON/protobuf/base64/gRPC " +
        "probes) so you don't try to decode ciphertext. Flags encrypted transports (e.g. WhatsApp " +
        "Noise/E2E) that passive MITM can't decode. Input an exchange body or raw hex/base64.",
      inputSchema: {
        id: z.string().optional(),
        side: z.enum(["request", "response"]).optional(),
        hex: z.string().optional(),
        base64: z.string().optional(),
      },
    },
    async (args) => {
      const buf = resolveBuffer(args);
      if (!buf || buf.length === 0) return text("No bytes to classify (check id/side/hex/base64).");
      const ex = args.id ? store.get(args.id) : undefined;
      const headers = args.side === "request" ? ex?.requestHeaders : ex?.responseHeaders;
      return text(
        classify(buf, {
          host: ex?.host,
          isWebSocket: ex?.isWebSocket,
          contentType: headers ? headerValue(headers, "content-type") : undefined,
        }),
      );
    },
  );

  server.registerTool(
    "protobuf_diff",
    {
      title: "Diff two protobuf messages",
      description:
        "Decode two exchanges' bodies as protobuf and diff them by field path - surfaces which fields " +
        "change between requests (cursors, tokens, ids) vs stay constant. Ideal for reverse-engineering " +
        "an API for automation.",
      inputSchema: {
        a: z.string().describe("First exchange id."),
        b: z.string().describe("Second exchange id."),
        side: z.enum(["request", "response"]).describe("Which body to compare."),
      },
    },
    async ({ a, b, side }) => {
      const ba = resolveBuffer({ id: a, side });
      const bb = resolveBuffer({ id: b, side });
      const na = ba && pbParse(ba);
      const nb = bb && pbParse(bb);
      if (!na || !nb) return text("One or both bodies are not decodable protobuf.");
      const d = pbDiff(na, nb);
      const fmt = (arr: { path: string; value?: string; a?: string; b?: string }[]) =>
        arr.length ? arr.map((x) => `  ${x.path}: ${x.a !== undefined ? `${x.a} -> ${x.b}` : x.value}`).join("\n") : "  (none)";
      return text(
        `Changed (${d.changed.length}):\n${fmt(d.changed)}\n\n` +
          `Only in A (${d.onlyA.length}):\n${fmt(d.onlyA)}\n\n` +
          `Only in B (${d.onlyB.length}):\n${fmt(d.onlyB)}`,
      );
    },
  );

  server.registerTool(
    "clear_traffic",
    { title: "Clear traffic", description: "Drop all captured exchanges.", inputSchema: {} },
    async () => text(`Cleared ${store.clear()} exchange(s).`),
  );

  server.registerTool(
    "export_har",
    {
      title: "Export HAR",
      description: "Export captured traffic (optionally filtered) to a .har file.",
      inputSchema: {
        outPath: z.string().optional().describe("Output path. Default ./exports/traffic-<ts>.har"),
        host: z.string().optional(),
        urlPattern: z.string().optional(),
        limit: z.number().int().optional(),
      },
    },
    async ({ outPath, host, urlPattern, limit }) => {
      const har = store.toHar({ host, urlPattern, limit });
      const file = outPath ?? path.join(process.cwd(), "exports", `traffic-${Date.now()}.har`);
      await fs.mkdir(path.dirname(file), { recursive: true });
      await fs.writeFile(file, JSON.stringify(har, null, 2));
      return text(`Wrote HAR to ${file}`);
    },
  );

  server.registerTool(
    "import_har",
    {
      title: "Import HAR",
      description:
        "Load a .har file (e.g. exported from HTTP Toolkit or a browser) into the store so it can " +
        "be listed, searched and inspected like live traffic.",
      inputSchema: {
        path: z.string().describe("Path to the .har file."),
        clearFirst: z.boolean().optional().describe("Clear existing traffic before importing."),
      },
    },
    async ({ path: harPath, clearFirst }) => {
      const raw = await fs.readFile(harPath, "utf8");
      const har = JSON.parse(raw);
      if (clearFirst) store.clear();
      const n = store.importHar(har);
      return text(`Imported ${n} exchange(s) from ${harPath}. Total in store: ${store.count()}.`);
    },
  );

  // ---- Rules ------------------------------------------------------------

  const ruleResult = (label: string, id: string) => text(`Added ${label} rule ${id}.`);

  server.registerTool(
    "add_mock_rule",
    {
      title: "Mock response",
      description: "Reply to matching requests with a fixed response (passes through everything else).",
      inputSchema: {
        ...matchShape,
        status: z.number().int().min(100).max(599).describe("HTTP status to return."),
        body: z.string().optional().describe("Raw response body."),
        json: z.any().optional().describe("JSON body (sets Content-Type: application/json)."),
        headers: z.record(z.string()).optional(),
      },
    },
    async ({ method, urlPattern, status, body, json, headers }) => {
      const rule = await proxy.addRule(
        { method, urlPattern } as RuleMatch,
        { type: "mock", status, body, json, headers },
      );
      return ruleResult("mock", rule.id);
    },
  );

  server.registerTool(
    "add_error_rule",
    {
      title: "Inject error",
      description: "Break matching requests: reset/close the connection or hang (timeout).",
      inputSchema: { ...matchShape, kind: z.enum(["reset", "timeout", "close"]) },
    },
    async ({ method, urlPattern, kind }) => {
      const rule = await proxy.addRule({ method, urlPattern } as RuleMatch, { type: "error", kind });
      return ruleResult("error", rule.id);
    },
  );

  server.registerTool(
    "add_delay_rule",
    {
      title: "Add latency",
      description: "Delay matching requests by N ms, then pass them through normally.",
      inputSchema: { ...matchShape, ms: z.number().int().min(1).describe("Delay in milliseconds.") },
    },
    async ({ method, urlPattern, ms }) => {
      const rule = await proxy.addRule({ method, urlPattern } as RuleMatch, { type: "delay", ms });
      return ruleResult("delay", rule.id);
    },
  );

  server.registerTool(
    "add_redirect_rule",
    {
      title: "Redirect request",
      description: "Transparently forward matching requests to a different absolute URL.",
      inputSchema: { ...matchShape, toUrl: z.string().url().describe("Absolute target URL.") },
    },
    async ({ method, urlPattern, toUrl }) => {
      const rule = await proxy.addRule({ method, urlPattern } as RuleMatch, { type: "redirect", toUrl });
      return ruleResult("redirect", rule.id);
    },
  );

  server.registerTool(
    "add_modify_request_rule",
    {
      title: "Modify request",
      description: "Rewrite headers/body on matching requests, then pass through.",
      inputSchema: {
        ...matchShape,
        setHeaders: z.record(z.string()).optional(),
        removeHeaders: z.array(z.string()).optional(),
        replaceBody: z.string().optional(),
      },
    },
    async ({ method, urlPattern, setHeaders, removeHeaders, replaceBody }) => {
      const rule = await proxy.addRule(
        { method, urlPattern } as RuleMatch,
        { type: "modify-request", setHeaders, removeHeaders, replaceBody },
      );
      return ruleResult("modify-request", rule.id);
    },
  );

  server.registerTool(
    "list_rules",
    { title: "List rules", description: "List active interception rules.", inputSchema: {} },
    async () => {
      const rules = proxy.listRules();
      if (rules.length === 0) return text("No rules.");
      return text(rules.map((r) => `[${r.id}] ${JSON.stringify(r.match)} -> ${JSON.stringify(r.action)}`).join("\n"));
    },
  );

  server.registerTool(
    "remove_rule",
    { title: "Remove rule", description: "Remove a rule by id.", inputSchema: { id: z.string() } },
    async ({ id }) => text((await proxy.removeRule(id)) ? `Removed ${id}.` : `No rule ${id}.`),
  );

  server.registerTool(
    "clear_rules",
    { title: "Clear rules", description: "Remove all rules.", inputSchema: {} },
    async () => {
      await proxy.clearRules();
      return text("All rules cleared.");
    },
  );

  // ---- ADB / device -----------------------------------------------------

  server.registerTool(
    "adb_devices",
    { title: "List adb devices", description: "List connected adb devices/emulators.", inputSchema: {} },
    async () => {
      const devices = await adb.listDevices();
      if (devices.length === 0) return text("No devices. Try adb_connect with the emulator host:port.");
      return text(devices.map((d) => `${d.serial}\t${d.state}`).join("\n"));
    },
  );

  server.registerTool(
    "adb_connect",
    {
      title: "adb connect",
      description:
        "Connect to an emulator over TCP. Accepts a host:port or a preset name " +
        "(nox, memu, bluestacks, ldplayer). See list_emulator_presets.",
      inputSchema: { target: z.string().describe("host:port (e.g. 127.0.0.1:62001) or preset name") },
    },
    async ({ target }) => text(await adb.connect(target)),
  );

  server.registerTool(
    "list_emulator_presets",
    {
      title: "List emulator presets",
      description: "Known emulators with their default adb connect host:port.",
      inputSchema: {},
    },
    async () =>
      text(
        Object.entries(EMULATOR_PRESETS)
          .map(([k, v]) => `${k}\t${v.hostPort || "(auto)"}\t${v.note}`)
          .join("\n"),
      ),
  );

  server.registerTool(
    "adb_install_cert",
    {
      title: "Install CA (system store)",
      description:
        "Push the proxy CA into the device's SYSTEM trust store via adb (no Magisk needed on Nox/MEmu). " +
        "Trusted by all apps and invisible to user-store anti-MITM checks. Fails on hard-pinned apps.",
      inputSchema: { serial: z.string().optional().describe("Target device serial (if multiple).") },
    },
    async ({ serial }) => {
      await proxy.ensureCa();
      const res = await adb.installSystemCert(proxy.caPath, serial);
      return text(`Installed CA as ${res.remotePath} (method: ${res.method}).\n${res.log}`);
    },
  );

  server.registerTool(
    "adb_set_proxy",
    {
      title: "Set device proxy",
      description: "Route device traffic through host:port via adb (no WiFi UI needed).",
      inputSchema: {
        hostPort: z.string().describe("Proxy as <host-ip>:<port>, e.g. 10.126.193.90:8000"),
        serial: z.string().optional(),
      },
    },
    async ({ hostPort, serial }) => {
      await adb.setProxy(hostPort, serial);
      return text(`Device proxy set to ${hostPort}.`);
    },
  );

  server.registerTool(
    "adb_clear_proxy",
    {
      title: "Clear device proxy",
      description: "Remove the device global proxy via adb.",
      inputSchema: { serial: z.string().optional() },
    },
    async ({ serial }) => {
      await adb.clearProxy(serial);
      return text("Device proxy cleared.");
    },
  );

  server.registerTool(
    "adb_setup",
    {
      title: "One-shot device setup",
      description:
        "Convenience: start proxy (if needed), install the system CA, and set the device proxy in one step.",
      inputSchema: {
        hostIp: z.string().describe("Your machine's LAN IP reachable from the emulator."),
        port: z.number().int().optional().describe("Proxy port (default 8000)."),
        serial: z.string().optional(),
      },
    },
    async ({ hostIp, port, serial }) => {
      const p = port ?? 8000;
      if (!proxy.running) await proxy.start(p);
      const cert = await adb.installSystemCert(proxy.caPath, serial);
      await adb.setProxy(`${hostIp}:${p}`, serial);
      return text(
        `Proxy on ${hostIp}:${p}.\nCA installed at ${cert.remotePath} (${cert.method}).\nDevice proxy set.\n` +
          "Reboot the emulator if existing apps don't pick up the new system cert.",
      );
    },
  );

  // ---- Transparent interception (iptables) ------------------------------

  server.registerTool(
    "adb_enable_transparent",
    {
      title: "Enable transparent capture",
      description:
        "Redirect ALL device TCP :80/:443 to the proxy via iptables DNAT - captures every app's " +
        "traffic with no companion app and no VPN dialog. Requires root (Nox/MEmu out of the box).",
      inputSchema: {
        hostPort: z.string().describe("Proxy as <host-ip>:<port>, e.g. 10.126.193.90:8000"),
        serial: z.string().optional(),
      },
    },
    async ({ hostPort, serial }) => text("iptables DNAT enabled:\n" + (await adb.enableTransparent(hostPort, serial))),
  );

  server.registerTool(
    "adb_disable_transparent",
    {
      title: "Disable transparent capture",
      description: "Remove the iptables DNAT redirect rules.",
      inputSchema: {
        hostPort: z.string().describe("Same <host-ip>:<port> used when enabling."),
        serial: z.string().optional(),
      },
    },
    async ({ hostPort, serial }) => text(await adb.disableTransparent(hostPort, serial)),
  );

  server.registerTool(
    "adb_transparent_status",
    {
      title: "Transparent status",
      description: "Show the device's nat OUTPUT chain (active DNAT redirects).",
      inputSchema: { serial: z.string().optional() },
    },
    async ({ serial }) => text(await adb.transparentStatus(serial)),
  );

  server.registerTool(
    "adb_setup_transparent",
    {
      title: "One-shot transparent setup",
      description:
        "Start proxy (if needed), install the system CA, and enable transparent iptables capture - " +
        "the closest adb-only equivalent of HTTP Toolkit's VPN mode, with zero on-device dialogs.",
      inputSchema: {
        hostIp: z.string().describe("Your machine's LAN IP reachable from the emulator."),
        port: z.number().int().optional().describe("Proxy port (default 8000)."),
        serial: z.string().optional(),
      },
    },
    async ({ hostIp, port, serial }) => {
      const p = port ?? 8000;
      if (!proxy.running) await proxy.start(p);
      const cert = await adb.installSystemCert(proxy.caPath, serial);
      const rules = await adb.enableTransparent(`${hostIp}:${p}`, serial);
      return text(
        `Proxy on ${hostIp}:${p}.\nCA installed at ${cert.remotePath} (${cert.method}).\n` +
          `Transparent redirect:\n${rules}\n` +
          "All :80/:443 traffic now flows through the proxy. Reboot apps if needed.",
      );
    },
  );
}
