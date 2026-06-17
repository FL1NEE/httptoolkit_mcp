#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { TrafficStore } from "./traffic-store.js";
import { ProxyManager } from "./proxy-manager.js";
import { Adb } from "./adb.js";
import { registerTools } from "./tools.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main(): Promise<void> {
  const certDir = process.env.HTMCP_CERT_DIR ?? path.join(__dirname, "..", "certs");
  const adbPath = process.env.HTMCP_ADB_PATH;

  const store = new TrafficStore();
  const proxy = new ProxyManager(store, certDir);
  const adb = new Adb(adbPath);

  const server = new McpServer({ name: "httptoolkit-mcp", version: "0.1.0" });
  registerTools(server, proxy, store, adb);

  // Stop the proxy cleanly on shutdown.
  const shutdown = async () => {
    await proxy.stop().catch(() => {});
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Never log to stdout - it is the MCP transport. Use stderr if needed.
  process.stderr.write("httptoolkit-mcp ready (stdio)\n");
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err?.stack ?? err}\n`);
  process.exit(1);
});
