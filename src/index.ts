#!/usr/bin/env node
/**
 * cloudflare-dns-mcp-server
 *
 * Streamable HTTP MCP server (stateless JSON mode) exposing Cloudflare DNS
 * management tools to any MCP-compatible client. Also supports stdio for
 * clients that launch local subprocess servers (TRANSPORT=stdio).
 *
 * Environment:
 *   CLOUDFLARE_API_TOKEN  (required)  scoped Cloudflare API token (Zone → DNS → Edit)
 *   MCP_AUTH_TOKEN        (optional)  if set, HTTP clients must send `Authorization: Bearer <token>`
 *   ALLOW_UNAUTHENTICATED (optional)  'true' permits a non-loopback bind without MCP_AUTH_TOKEN (auth must be terminated upstream)
 *   HOST                  (optional)  bind address, default 127.0.0.1
 *   PORT                  (optional)  default 8787
 *   TRANSPORT             (optional)  'http' (default) or 'stdio'
 *   ALLOWED_ORIGINS       (optional)  comma-separated browser Origins to allow, in addition to localhost
 */
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools, TOOL_COUNT } from "./tools.js";

const SERVER_NAME = "cloudflare-dns-mcp-server";
const SERVER_VERSION = "1.0.0";
const INSTRUCTIONS =
  "Tools for managing DNS records on the connected Cloudflare account. " +
  "Zones can be referenced by domain name or zone ID. Record edits require the record's ID — " +
  "always call cloudflare_list_dns_records first to find it. TTL of 1 means 'Auto'. " +
  "Consider cloudflare_export_zone as a backup before bulk or risky changes.";

function buildServer(): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION }, { instructions: INSTRUCTIONS });
  registerTools(server);
  return server;
}

function log(...args: unknown[]): void {
  // stderr only — stdout must stay clean for stdio transport.
  console.error(`[${SERVER_NAME}]`, ...args);
}

async function runStdio(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("running on stdio");
}

function originAllowed(origin: string): boolean {
  const extra = (process.env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (extra.includes(origin)) return true;
  try {
    let host = new URL(origin).hostname;
    // WHATWG URL keeps IPv6 literals bracketed (e.g. '[::1]'); strip them before comparing.
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  } catch {
    return false;
  }
}

async function runHttp(): Promise<void> {
  const app = express();

  const authToken = process.env.MCP_AUTH_TOKEN;

  app.get("/healthz", (_req, res) => {
    res.json({ ok: true, server: SERVER_NAME, version: SERVER_VERSION });
  });

  // Auth + DNS-rebinding protection for the MCP endpoint.
  app.use("/mcp", (req, res, next) => {
    const origin = req.headers.origin;
    if (origin && !originAllowed(origin)) {
      res.status(403).json({ error: "Forbidden: origin not allowed" });
      return;
    }
    if (authToken) {
      const header = req.headers.authorization ?? "";
      if (header !== `Bearer ${authToken}`) {
        res.set("WWW-Authenticate", "Bearer");
        res.status(401).json({ error: "Unauthorized: send 'Authorization: Bearer <MCP_AUTH_TOKEN>'" });
        return;
      }
    }
    next();
  });

  // Stateless: fresh server + transport per request (no sessions, plain JSON responses).
  // Body parsing is attached here (not globally) so the /mcp auth+origin middleware above
  // runs FIRST — a malformed JSON POST from an unauthenticated client is rejected before parsing.
  app.post("/mcp", express.json({ limit: "1mb" }), async (req, res) => {
    try {
      const server = buildServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      log("request error:", err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  });

  // Stateless JSON mode: no SSE stream to GET, no session to DELETE.
  const methodNotAllowed = (_req: express.Request, res: express.Response): void => {
    res.set("Allow", "POST");
    res.status(405).json({ error: "Method not allowed — POST JSON-RPC messages to this endpoint" });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  // Final error handler: never leaks stack traces (regardless of NODE_ENV). Body-parse and other
  // client (4xx) errors get a minimal JSON reply; anything else is logged (message only) as a 500.
  app.use((err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction): void => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const e = err as { type?: string; status?: number; statusCode?: number };
    const status = e.status ?? e.statusCode;
    if (e.type === "entity.parse.failed" || (typeof status === "number" && status >= 400 && status < 500)) {
      res.status(typeof status === "number" ? status : 400).json({ error: "Bad request: malformed or unacceptable request body" });
      return;
    }
    log("request error:", err instanceof Error ? err.message : String(err));
    res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
  });

  const host = process.env.HOST ?? "127.0.0.1";
  const port = Number.parseInt(process.env.PORT ?? "8787", 10);

  // Normalize only for the auth-guard decision — app.listen still gets the user's original HOST.
  const normalizedHost = host.trim().toLowerCase();
  const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);
  if (!authToken && !LOOPBACK_HOSTS.has(normalizedHost)) {
    if (process.env.ALLOW_UNAUTHENTICATED === "true") {
      log(
        "WARNING: server is binding to a non-localhost address without MCP_AUTH_TOKEN set. " +
          "Anyone who can reach this port can edit your DNS. Set MCP_AUTH_TOKEN before exposing it. " +
          "ALLOW_UNAUTHENTICATED=true is set, so starting anyway — make sure auth is terminated upstream.",
      );
    } else {
      log(
        "ERROR: refusing to start. Binding a non-localhost address without MCP_AUTH_TOKEN set would let " +
          "anyone who can reach this port edit your DNS. Set MCP_AUTH_TOKEN, or set ALLOW_UNAUTHENTICATED=true " +
          "only when auth is terminated upstream (e.g. Cloudflare Access in front of a tunnel).",
      );
      process.exit(1);
    }
  }

  const httpServer = app.listen(port, host, () => {
    log(`running on http://${host}:${port}/mcp (${TOOL_COUNT} tools, auth ${authToken ? "ON" : "OFF"})`);
  });
  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      log(`ERROR: port ${port} is already in use. Stop the other process or set PORT to a free port.`);
    } else {
      log("ERROR: failed to start HTTP server:", err.message);
    }
    process.exit(1);
  });
}

function main(): void {
  if (!process.env.CLOUDFLARE_API_TOKEN) {
    log(
      "ERROR: CLOUDFLARE_API_TOKEN is not set. Create a scoped token (template 'Edit zone DNS', " +
        "limited to your zones) at https://dash.cloudflare.com/profile/api-tokens and export it before starting.",
    );
    process.exit(1);
  }
  const transport = (process.env.TRANSPORT ?? "http").toLowerCase();
  const run = transport === "stdio" ? runStdio : runHttp;
  run().catch((err) => {
    log("fatal:", err);
    process.exit(1);
  });
}

main();
