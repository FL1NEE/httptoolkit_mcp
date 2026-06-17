import http from "node:http";
import os from "node:os";
import path from "node:path";
import { TrafficStore, bodyText } from "../dist/traffic-store.js";
import { ProxyManager } from "../dist/proxy-manager.js";
import { decodeRaw } from "../dist/protobuf.js";
import { renderBody, parseResponseCookies } from "../dist/body-format.js";

const PROXY_PORT = 8999;

// Forward-proxy GET: send absolute-URI request line to the proxy.
function proxyGet(targetUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const req = http.request(
      { host: "127.0.0.1", port: PROXY_PORT, method: "GET", path: targetUrl, headers: { Host: u.host } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      },
    );
    req.on("error", reject);
    req.end();
  });
}

let failures = 0;
function check(name, cond) {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
}

const target = http.createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("hello-from-target");
});
await new Promise((r) => target.listen(0, "127.0.0.1", r));
const targetUrl = `http://127.0.0.1:${target.address().port}/api/data`;

const store = new TrafficStore();
const proxy = new ProxyManager(store, path.join(os.tmpdir(), "htmcp-test-certs"));
await proxy.start(PROXY_PORT);

// 1) passthrough + capture
const r1 = await proxyGet(targetUrl);
await new Promise((r) => setTimeout(r, 100));
check("passthrough returns target body", r1.body === "hello-from-target");
check("exchange captured", store.count() === 1);
const ex = store.list()[0];
check("captured status 200", ex?.statusCode === 200);
check("captured response body", bodyText(ex?.responseBody) === "hello-from-target");
check("host parsed", ex?.host === `127.0.0.1:${target.address().port}`);

// 2) mock rule (also exercises rebuild + event re-subscription)
await proxy.addRule({ urlPattern: "/api/data" }, { type: "mock", status: 503, body: "mocked!" });
const r2 = await proxyGet(targetUrl);
await new Promise((r) => setTimeout(r, 100));
check("mock status applied", r2.status === 503);
check("mock body applied", r2.body === "mocked!");
check("capture still works after rebuild", store.count() === 2);

// 3) remove rule -> passthrough again
await proxy.clearRules();
const r3 = await proxyGet(targetUrl);
check("passthrough after clearRules", r3.body === "hello-from-target");

// 4) HAR export + re-import round-trip
const har = store.toHar();
check("HAR has entries", Array.isArray(har.log?.entries) && har.log.entries.length >= 3);
const store2 = new TrafficStore();
const n = store2.importHar(har);
check("HAR import count matches", n === har.log.entries.length);
check("HAR import preserves body", bodyText(store2.list({ urlPattern: "/api/data" })[0]?.responseBody)?.length > 0);

await proxy.stop();
target.close();

// 5) protobuf raw decode: message { 1: 150 (varint), 2: "testing" (string) }
const pb = Buffer.from([0x08, 0x96, 0x01, 0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]);
const decoded = decodeRaw(pb);
check("protobuf decodes varint field", decoded?.includes("1: 150"));
check("protobuf decodes string field", decoded?.includes('2: "testing"'));
const pbBody = { base64: pb.toString("base64"), size: pb.length, truncated: false };
check(
  "renderBody protobuf auto-detect",
  renderBody(pbBody, { "content-type": "application/x-protobuf" }, "auto").includes('"testing"'),
);

// 6) cookie parsing
const cookies = parseResponseCookies({ "set-cookie": ["sid=abc123; Path=/; HttpOnly; Secure", "lang=ru"] });
check("parses 2 set-cookies", cookies.length === 2);
check("parses cookie value", cookies[0].name === "sid" && cookies[0].value === "abc123");
check("parses cookie attrs", cookies[0].attributes?.httponly === true && cookies[0].attributes?.path === "/");
console.log(failures === 0 ? "\nALL GOOD" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
