import { WebSocketServer, WebSocket } from "ws";
import os from "node:os";
import path from "node:path";
import { TrafficStore, bodyText } from "../dist/traffic-store.js";
import { ProxyManager } from "../dist/proxy-manager.js";

const PROXY_PORT = 8997;
let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
};

// Upstream echo server.
const wss = new WebSocketServer({ port: 0, host: "127.0.0.1" });
wss.on("connection", (ws) => ws.on("message", (m) => ws.send("echo:" + m.toString())));
await new Promise((r) => wss.on("listening", r));
const upstreamPort = wss.address().port;

const store = new TrafficStore();
const proxy = new ProxyManager(store, path.join(os.tmpdir(), "htmcp-test-certs"));
await proxy.start(PROXY_PORT);

// Connect through the proxy transparently: TCP to the proxy, Host = upstream.
const ws = new WebSocket(`ws://127.0.0.1:${PROXY_PORT}/chat`, {
  headers: { Host: `127.0.0.1:${upstreamPort}` },
});

const got = await new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error("ws timeout")), 6000);
  ws.on("open", () => ws.send("hello-ws"));
  ws.on("message", (m) => {
    clearTimeout(t);
    resolve(m.toString());
  });
  ws.on("error", reject);
}).catch((e) => `ERR:${e.message}`);

check("ws echo round-trips through proxy", got === "echo:hello-ws");
await new Promise((r) => setTimeout(r, 200));

const wsEx = store.list().find((e) => e.isWebSocket);
check("websocket exchange captured", !!wsEx);
check("captured both messages", (wsEx?.wsMessages?.length ?? 0) >= 2);
const sent = wsEx?.wsMessages?.find((m) => m.direction === "received"); // client->server seen as 'received'
check("captured a message body", wsEx?.wsMessages?.some((m) => bodyText(m.body)?.includes("hello-ws")));
check("captured echo body", wsEx?.wsMessages?.some((m) => bodyText(m.body)?.includes("echo:hello-ws")));

ws.close();
await proxy.stop();
wss.close();
console.log(failures === 0 ? "\nALL GOOD" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
