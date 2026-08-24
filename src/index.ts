#!/usr/bin/env node
/**
 * cloudflare-dns-mcp-server
 *
 * Streamable HTTP MCP server (stateless JSON mode) exposing Cloudflare DNS
 * management tools to any MCP-compatible client. Also supports stdio for
 * clients that launch local subprocess servers (TRANSPORT=stdio).
 *
 * Environment:
 *   CLOUDFLARE_API_TOKEN  (required unless gateway mode) scoped Cloudflare API token (Zone → DNS → Edit)
 *   MCP_AUTH_TOKEN        (optional)  if set, HTTP clients must send `Authorization: Bearer <token>`
 *   ALLOW_UNAUTHENTICATED (optional)  'true' permits a non-loopback bind without MCP_AUTH_TOKEN (auth must be terminated upstream)
 *   HOST                  (optional)  bind address, default 127.0.0.1
 *   PORT                  (optional)  default 8787
 *   TRANSPORT             (optional)  'http' (default) or 'stdio'
 *   ALLOWED_ORIGINS       (optional)  comma-separated browser Origins to allow, in addition to localhost
 *
 * Gateway (multi-tenant) mode — HTTP transport only (see README "Gateway mode"):
 *   GATEWAY_ENABLE            'true' turns on per-agent bearer auth; each request runs with its agent's own token
 *   ADMIN_PORT                localhost-only admin panel port (default 8788)
 *   ADMIN_PASSWORD            admin-panel password (auto-generated & printed once to stderr if unset)
 *   GATEWAY_DATA_DIR          directory for agents.json (and, with the file store, the encrypted secrets)
 *   GATEWAY_SECRET_STORE      'file' forces the encrypted-file backend; otherwise macOS keychain when available
 *   GATEWAY_MASTER_PASSPHRASE passphrase for the encrypted-file secret store (required when it is used)
 *   GATEWAY_PUBLIC_URL        optional public base URL of this /mcp server, used in connector snippets
 */
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools, TOOL_COUNT } from "./tools.js";
import { gatewayEnabled, runWithToken } from "./gateway/context.js";
import { loadStore, type AgentStore, type Agent } from "./gateway/agents.js";
import { selectSecretStore, ensureDataDir, type SecretStore } from "./gateway/store.js";
import { startAdminServer, resolveAdminPassword, extractBearer, DEFAULT_ADMIN_PORT } from "./gateway/admin.js";

const SERVER_NAME = "cloudflare-dns-mcp-server";
const SERVER_VERSION = "1.0.0";
const INSTRUCTIONS =
  "Tools for managing DNS records on the connected Cloudflare account. " +
  "Zones can be referenced by domain name or zone ID. Record edits require the record's ID — " +
  "always call cloudflare_list_dns_records first to find it. TTL of 1 means 'Auto'. " +
  "Consider cloudflare_export_zone as a backup before bulk or risky changes. " +
  "cloudflare_api_request makes raw Cloudflare v4 API calls to any endpoint the token can reach (not just DNS): " +
  "reads (GET/HEAD) are available by default, while mutating methods require CLOUDFLARE_API_PASSTHROUGH=full plus " +
  "confirm=true (CLOUDFLARE_API_PASSTHROUGH=off disables it entirely) — prefer the typed cloudflare_* tools whenever they fit. " +
  "Two Workers tools are off by default and enabled per operator opt-in: cloudflare_set_worker_secret_from_env sets a " +
  "Worker secret whose value is read from the SERVER's own environment (the model only names an allowlisted env var; the " +
  "value never passes through the model or output), and cloudflare_deploy_worker uploads/deploys a Worker script. Both " +
  "require confirm=true; see CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST / CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST and " +
  "CLOUDFLARE_WORKERS_DEPLOY_ENABLE.";

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
  const gateway = gatewayEnabled();

  // ---- Gateway (multi-tenant) mode setup. Each request is authenticated to ONE agent and runs with
  // that agent's own Cloudflare token; there is no process-wide MCP_AUTH_TOKEN. The admin panel (a
  // separate localhost-only server) manages the key/agent tables shared with the /mcp handler here. ----
  let gatewayCtx: { store: AgentStore; secretStore: SecretStore } | undefined;
  if (gateway) {
    const dataDir = process.env.GATEWAY_DATA_DIR;
    if (!dataDir) {
      log(
        "ERROR: gateway mode (GATEWAY_ENABLE=true) requires GATEWAY_DATA_DIR — it holds agents.json (key/agent " +
          "metadata) and, with GATEWAY_SECRET_STORE=file, the encrypted secrets. Set GATEWAY_DATA_DIR and restart.",
      );
      process.exit(1);
    }
    // Create the data dir if missing and, unconditionally + best-effort, tighten it to 0700 EVERY
    // startup — so even a pre-existing operator-created dir left world-readable by a lax umask is
    // locked down before agents.json / secrets.enc.json (themselves 0600) are written into it.
    ensureDataDir(dataDir);
    const store = loadStore(dataDir);
    const secretStore = selectSecretStore(dataDir);
    gatewayCtx = { store, secretStore };
    const adminPassword = resolveAdminPassword(log);
    const adminPort = Number.parseInt(process.env.ADMIN_PORT ?? String(DEFAULT_ADMIN_PORT), 10);
    startAdminServer({
      store,
      secretStore,
      password: adminPassword,
      port: adminPort,
      publicMcpUrl: process.env.GATEWAY_PUBLIC_URL,
      log,
    });
  }

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
    if (gatewayCtx) {
      // Gateway mode: the per-agent bearer table IS the auth. Resolve the presented bearer to an
      // ENABLED agent (findAgentByBearer skips disabled ones and compares hashes in constant time);
      // no/unknown/disabled bearer → 401. The resolved agent rides on res.locals to the POST handler.
      const bearer = extractBearer(typeof req.headers.authorization === "string" ? req.headers.authorization : undefined);
      const agent = bearer ? gatewayCtx.store.findAgentByBearer(bearer) : undefined;
      if (!agent) {
        res.set("WWW-Authenticate", "Bearer");
        res.status(401).json({ error: "Unauthorized: send 'Authorization: Bearer <agent bearer>'" });
        return;
      }
      (res.locals as { agent?: Agent }).agent = agent;
      next();
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
      // The stateless per-request MCP dance. In gateway mode this runs INSIDE runWithToken so that
      // apiToken() (cloudflare.ts) picks up the authenticated agent's own Cloudflare token from the
      // AsyncLocalStorage context — no global token is ever consulted.
      const handleRequest = async (): Promise<void> => {
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
      };

      if (gatewayCtx) {
        const agent = (res.locals as { agent?: Agent }).agent;
        if (!agent) {
          // Should be unreachable — the middleware 401s without a resolved agent — but fail closed.
          res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null });
          return;
        }
        const token = await gatewayCtx.secretStore.getSecret(agent.key_id);
        if (!token) {
          // The agent's key exists in metadata but its secret is unavailable (misconfiguration).
          log(`gateway: agent '${agent.name}' has no resolvable Cloudflare token for key ${agent.key_id}`);
          if (!res.headersSent) {
            res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
          }
          return;
        }
        await runWithToken({ cloudflareToken: token, agentName: agent.name }, handleRequest);
      } else {
        await handleRequest();
      }
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
  // In gateway mode the per-agent bearer table authenticates every /mcp request, so it satisfies the
  // "don't bind non-localhost without auth" guard exactly as MCP_AUTH_TOKEN does in single-tenant mode.
  const authSatisfied = !!authToken || gateway;
  if (!authSatisfied && !LOOPBACK_HOSTS.has(normalizedHost)) {
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
    const authDesc = gateway ? "gateway mode: per-agent bearer auth" : `auth ${authToken ? "ON" : "OFF"}`;
    log(`running on http://${host}:${port}/mcp (${TOOL_COUNT} tools, ${authDesc})`);
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
  const transport = (process.env.TRANSPORT ?? "http").toLowerCase();

  // Gateway (multi-tenant) mode applies to the HTTP transport only: it selects each agent's Cloudflare
  // token from a per-request bearer, which stdio (a single local subprocess with one token) has no
  // notion of. apiToken() also fails closed whenever GATEWAY_ENABLE=true, so a stdio process with the
  // flag set could not resolve a token at all. Refuse the combination with a clear message rather than
  // start a broken single-tenant server.
  if (transport === "stdio" && gatewayEnabled()) {
    log(
      "ERROR: GATEWAY_ENABLE=true is not supported with TRANSPORT=stdio. Gateway (multi-tenant) mode runs " +
        "only over HTTP, where a per-agent bearer selects each agent's Cloudflare token. For a local stdio " +
        "server, run single-tenant: unset GATEWAY_ENABLE and set CLOUDFLARE_API_TOKEN. For gateway mode, use TRANSPORT=http.",
    );
    process.exit(1);
  }

  // In gateway mode there is no single process-wide Cloudflare token — each agent brings its own — so
  // CLOUDFLARE_API_TOKEN is not required. Every other configuration still requires it.
  if (!gatewayEnabled() && !process.env.CLOUDFLARE_API_TOKEN) {
    log(
      "ERROR: CLOUDFLARE_API_TOKEN is not set. Create a scoped token (template 'Edit zone DNS', " +
        "limited to your zones) at https://dash.cloudflare.com/profile/api-tokens and export it before starting.",
    );
    process.exit(1);
  }

  const run = transport === "stdio" ? runStdio : runHttp;
  run().catch((err) => {
    log("fatal:", err);
    process.exit(1);
  });
}

main();
