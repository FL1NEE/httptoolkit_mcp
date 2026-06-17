import crypto from "node:crypto";
import zlib from "node:zlib";
import { classify, entropy } from "../dist/classify.js";

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
};

// JSON
const json = classify(Buffer.from(JSON.stringify({ a: 1, b: "x" })));
check("detects JSON", json.includes("JSON (valid)"));

// protobuf: { 1: 150, 2: "hi" }
const pb = Buffer.from([0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69]);
check("detects protobuf", classify(pb).includes("protobuf"));

// gzip
const gz = classify(zlib.gzipSync(Buffer.from("x".repeat(200))));
check("detects gzip magic", gz.includes("gzip"));

// random ciphertext -> high entropy, encrypted verdict
const rnd = crypto.randomBytes(512);
const rc = classify(rnd);
check("random has high entropy", entropy(rnd) > 7.5);
check("flags encrypted ciphertext", rc.includes("ENCRYPTED") || rc.includes("ciphertext"));

// WhatsApp host hint
const wa = classify(crypto.randomBytes(256), { host: "g.whatsapp.net", isWebSocket: true });
check("flags WhatsApp Noise/E2E", wa.toLowerCase().includes("whatsapp") || wa.toLowerCase().includes("noise"));

// base64 wrapper around protobuf (long enough to pass the base64 heuristic)
const pbLong = Buffer.concat([Buffer.from([0x08, 0x96, 0x01, 0x12, 0x11]), Buffer.from("hello-world-token")]);
const b64 = classify(Buffer.from(pbLong.toString("base64")));
check("detects base64 wrapper of protobuf", b64.includes("base64") && b64.includes("protobuf"));

console.log(failures === 0 ? "\nALL GOOD" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
