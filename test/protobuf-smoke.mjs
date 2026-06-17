import zlib from "node:zlib";
import { inspect, toText, parse, diff, unframeGrpc, tryDecompress, flatten } from "../dist/protobuf.js";

let failures = 0;
const check = (name, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
  if (!cond) failures++;
};

// --- helpers to build protobuf wire bytes ---
const varintField = (field, value) => {
  const bytes = [(field << 3) | 0];
  let v = value;
  do {
    let b = v & 0x7f;
    v >>>= 7;
    if (v) b |= 0x80;
    bytes.push(b);
  } while (v);
  return Buffer.from(bytes);
};
const ldField = (field, buf) => {
  const len = varintField(0, buf.length).subarray(1); // reuse varint encoder for length
  return Buffer.concat([Buffer.from([(field << 3) | 2]), len, buf]);
};

// inner message: { 1: 150, 2: "hi" }
const inner = Buffer.concat([varintField(1, 150), ldField(2, Buffer.from("hi"))]);

// 1) plain nested message
const msgA = Buffer.concat([varintField(1, 7), ldField(3, inner)]);
const nodesA = inspect(msgA);
check("decodes top varint", nodesA?.[0]?.varint === "7");
check("decodes nested message", !!nodesA?.[1]?.message);
check("nested string preserved", nodesA?.[1]?.message?.[1]?.string === "hi");

// 2) embedded gzip blob inside a field -> auto-decompressed + recursively decoded
const gz = zlib.gzipSync(inner);
const msgB = Buffer.concat([varintField(1, 1), ldField(5, gz)]);
const nodesB = inspect(msgB);
check("detects compressed field", nodesB?.[1]?.decompressed?.algo === "gzip");
check("decodes inside compressed", nodesB?.[1]?.decompressed?.message?.[0]?.varint === "150");
check("tryDecompress roundtrip", tryDecompress(gz)?.data.equals(inner));
const textB = toText(nodesB);
check("text shows [gzip] marker", textB.includes("[gzip]"));

// 3) gRPC framing: [flag=0][len BE][payload]
const frame = Buffer.concat([Buffer.from([0]), (() => { const b = Buffer.alloc(4); b.writeUInt32BE(inner.length); return b; })(), inner]);
const frames = unframeGrpc(frame);
check("unframes gRPC", frames?.length === 1 && frames[0].equals(inner));

// 4) diff: same shape, one changed scalar + one extra field
const msgC = Buffer.concat([varintField(1, 7), ldField(3, Buffer.concat([varintField(1, 999), ldField(2, Buffer.from("hi"))]))]);
const d = diff(parse(msgA), parse(msgC));
check("diff finds changed field", d.changed.some((c) => c.path === "3.1" && c.a === "150" && c.b === "999"));
check("diff no false positives on constant", !d.changed.some((c) => c.path === "3.2"));

// 5) YouTube-style: base64url protobuf nested inside a string field
const tokenBytes = Buffer.concat([varintField(1, 42), ldField(2, Buffer.from("CONTINUATION"))]);
const tokenB64url = tokenBytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const outer = ldField(9, Buffer.from(tokenB64url)); // a string field holding the token
const nodesT = inspect(outer);
check("string field still shown", nodesT?.[0]?.string === tokenB64url);
check("base64url token auto-decoded", nodesT?.[0]?.base64Decoded?.[0]?.varint === "42");
check("text shows [base64 protobuf]", toText(nodesT).includes("[base64 protobuf]"));
check("flatten descends into token", flatten(nodesT).some(([p]) => p === "9.1"));

console.log(failures === 0 ? "\nALL GOOD" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
