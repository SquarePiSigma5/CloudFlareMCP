/**
 * Gateway admin panel: a SEPARATE, localhost-only HTTP server for managing keys and agents.
 *
 * Security posture (see the design-review MUST-FIX list):
 *   - Binds 127.0.0.1 ONLY — never 0.0.0.0 — and is served on ADMIN_PORT, never the /mcp port.
 *   - Every /api/* request must present ADMIN_PASSWORD in the Authorization header; the comparison is
 *     constant-time (crypto.timingSafeEqual over sha256 digests, so it is also length-independent).
 *   - Every request (the HTML shell included) is rejected unless its Host — and its Origin, when
 *     present — is localhost/127.0.0.1/::1. That is the anti DNS-rebinding / anti-CSRF guard: a page on
 *     evil.example that resolves to 127.0.0.1 sends Host: evil.example and is refused.
 *   - No KEY secret and no stored bearer is EVER returned by any endpoint or written to a log. Agent
 *     serialization omits bearer_sha256 by construction (explicit field list, never a spread).
 *
 * The admin server shares the SAME in-memory AgentStore and SecretStore instances as the /mcp handler
 * (index.ts constructs one of each and passes them here), so an agent created in the panel authenticates
 * at /mcp immediately.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { AgentStore, Key, Agent } from "./agents.js";
import type { SecretStore } from "./store.js";

/** The only host the admin server ever binds to. Hard-coded — never overridable to 0.0.0.0. */
export const ADMIN_BIND_HOST = "127.0.0.1";
/** Default admin port when ADMIN_PORT is unset. */
export const DEFAULT_ADMIN_PORT = 8788;
/** Cap on an admin request body — key/agent payloads are tiny; anything larger is rejected. */
const MAX_BODY_BYTES = 64 * 1024;
/**
 * Minimum length below which an operator-CHOSEN ADMIN_PASSWORD earns a one-time weakness warning.
 * The auto-generated password (randomBytes(32) hex = 64 chars) is always well above this.
 */
const MIN_ADMIN_PASSWORD_LENGTH = 16;

// ====================================================================================
// Pure helpers (exported for unit testing) — no I/O, no secrets in, no secrets out.
// ====================================================================================

/** Hostnames we treat as loopback for the Host/Origin guards. */
const LOCAL_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * True when the HTTP Host header names a loopback host (any port). A MISSING Host is rejected: HTTP/1.1
 * requires it, and its absence is not something we want to treat as local. Handles "127.0.0.1:8788",
 * "localhost:8788", "[::1]:8788", and the port-less forms.
 */
export function hostHeaderIsLocal(host: string | undefined): boolean {
  if (!host) return false;
  let h = host.trim();
  if (h.startsWith("[")) {
    const end = h.indexOf("]");
    if (end === -1) return false;
    h = h.slice(1, end); // strip the IPv6 brackets; ignore any :port after ']'
  } else {
    const colon = h.indexOf(":");
    if (colon !== -1) h = h.slice(0, colon); // strip :port
  }
  return LOCAL_HOSTNAMES.has(h.toLowerCase());
}

/**
 * True when the Origin header is absent (not a cross-origin browser request) OR names a loopback host.
 * A present-but-non-local Origin — or the opaque "null" origin — is rejected.
 */
export function originIsLocal(origin: string | undefined): boolean {
  if (origin === undefined) return true;
  if (origin === "null" || origin === "") return false;
  try {
    let host = new URL(origin).hostname;
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    return LOCAL_HOSTNAMES.has(host.toLowerCase());
  } catch {
    return false;
  }
}

/** Extract the token from an `Authorization: Bearer <token>` header, or undefined. */
export function extractBearer(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m ? m[1] : undefined;
}

/**
 * Constant-time string equality. Both inputs are sha256-hashed first, so the compared buffers are
 * always 32 bytes — timingSafeEqual never sees unequal lengths, and no length is leaked either.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb);
}

/** Serialize a Key for the API — id/name/created_at only (a Key carries no secret material anyway). */
export function serializeKey(k: Key): { id: string; name: string; created_at: string } {
  return { id: k.id, name: k.name, created_at: k.created_at };
}

/**
 * Serialize an Agent for the API. Fields are listed EXPLICITLY — bearer_sha256 is never spread in, so
 * the stored bearer hash can never leak through any admin response.
 */
export function serializeAgent(
  a: Agent,
  keyName: string | undefined,
): { id: string; name: string; key_id: string; key_name: string | null; enabled: boolean; created_at: string } {
  return {
    id: a.id,
    name: a.name,
    key_id: a.key_id,
    key_name: keyName ?? null,
    enabled: a.enabled,
    created_at: a.created_at,
  };
}

/** Lowercase a name into a connector-config key: [a-z0-9_-] only, collapsed dashes. */
function connectorSlug(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  return slug || "agent";
}

/**
 * Build a ready-to-paste MCP connector config for a freshly-minted bearer.
 *
 * `publicUrl` is the operator-configured public base of the /mcp server (GATEWAY_PUBLIC_URL). When it
 * is unset we emit an obvious placeholder host for the operator to replace — the admin server is
 * localhost-only and cannot know its own public URL.
 */
export function buildConnectorSnippet(agentName: string, bearer: string, publicUrl: string | undefined): string {
  let base = (publicUrl ?? "").trim().replace(/\/+$/, "");
  if (!base) base = "https://<your-mcp-host>";
  const url = base.endsWith("/mcp") ? base : `${base}/mcp`;
  const config = {
    mcpServers: {
      [`cloudflare-${connectorSlug(agentName)}`]: {
        url,
        headers: { Authorization: `Bearer ${bearer}` },
      },
    },
  };
  return JSON.stringify(config, null, 2);
}

// ====================================================================================
// Token validation probe — direct, host-pinned call to Cloudflare that never echoes the token.
// ====================================================================================

/** Fixed, host-pinned Cloudflare endpoints for the optional token probe. */
const CF_VERIFY_URL = "https://api.cloudflare.com/client/v4/user/tokens/verify";
const CF_ZONES_URL = "https://api.cloudflare.com/client/v4/zones?per_page=1";

/**
 * Probe a Cloudflare token's validity WITHOUT ever returning or logging it.
 *
 * Tries GET /user/tokens/verify first; account-scoped tokens can be forbidden there (403) yet still be
 * valid, so a non-OK verify falls back to GET /zones. Only a boolean + a short non-sensitive detail
 * string is returned. Any failure (network, timeout) is reported as invalid rather than thrown, since
 * this is advisory.
 */
export async function probeCloudflareToken(token: string): Promise<{ valid: boolean; detail: string }> {
  const auth = { Authorization: `Bearer ${token}` };
  try {
    const res = await fetch(CF_VERIFY_URL, { headers: auth, signal: AbortSignal.timeout(15_000) });
    if (res.ok) {
      const body = (await res.json().catch(() => undefined)) as
        | { success?: boolean; result?: { status?: string } }
        | undefined;
      if (body?.success === true && body.result?.status === "active") {
        return { valid: true, detail: "token verified (active)" };
      }
      return { valid: false, detail: "token is not active" };
    }
    // verify was non-OK (often 403 for account-scoped tokens) — fall back to a zones read.
    const zres = await fetch(CF_ZONES_URL, { headers: auth, signal: AbortSignal.timeout(15_000) });
    if (zres.ok) return { valid: true, detail: "token can list zones" };
    return { valid: false, detail: `token rejected (verify HTTP ${res.status}, zones HTTP ${zres.status})` };
  } catch {
    return { valid: false, detail: "could not reach the Cloudflare API to validate" };
  }
}

// ====================================================================================
// Request plumbing.
// ====================================================================================

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

/** Read and JSON-parse a request body, capped at MAX_BODY_BYTES. Empty body → {}. */
function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (c: Buffer) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error("Request body too large."));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          return reject(new Error("Request body must be a JSON object."));
        }
        resolve(parsed as Record<string, unknown>);
      } catch {
        reject(new Error("Request body is not valid JSON."));
      }
    });
    req.on("error", reject);
  });
}

/** A store error whose message is safe to surface to the localhost admin (contains ids/names, no secrets). */
function statusForStoreError(message: string): number {
  if (/^No (key|agent) with id/i.test(message)) return 404;
  if (/still referenced|Cannot delete key/i.test(message)) return 409;
  return 400;
}

function requireString(body: Record<string, unknown>, field: string): string {
  const v = body[field];
  if (typeof v !== "string" || v.trim() === "") {
    throw new HttpError(400, `'${field}' is required and must be a non-empty string.`);
  }
  return v;
}

class HttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

export interface AdminServerOptions {
  store: AgentStore;
  secretStore: SecretStore;
  /** The admin password (already resolved: env value or the freshly generated one). */
  password: string;
  /** Port to bind on 127.0.0.1. */
  port: number;
  /** Operator-configured public base URL of the /mcp server, for connector snippets (optional). */
  publicMcpUrl?: string;
  /** stderr logger shared with index.ts. Never called with secrets/bearers/passwords. */
  log: (...args: unknown[]) => void;
}

/**
 * Resolve the admin password: use ADMIN_PASSWORD when set to a non-empty value; otherwise generate a
 * strong random one (crypto.randomBytes(32) hex = 256 bits) and print it ONCE to stderr so the operator
 * can log in. The generated password is returned to the caller and never persisted.
 *
 * When the operator DID set ADMIN_PASSWORD but it is shorter than MIN_ADMIN_PASSWORD_LENGTH, we emit a
 * single stderr warning that a short admin password is weak — the password VALUE is never logged. This
 * is the real control (the admin panel already binds localhost-only and compares in constant time, so
 * rate limiting buys almost nothing); a long random password, or leaving it unset to auto-generate a
 * 256-bit one, is the recommendation.
 */
export function resolveAdminPassword(log: (...args: unknown[]) => void): string {
  const fromEnv = process.env.ADMIN_PASSWORD;
  if (fromEnv && fromEnv.trim() !== "") {
    if (fromEnv.length < MIN_ADMIN_PASSWORD_LENGTH) {
      log(
        `WARNING: ADMIN_PASSWORD is set but is shorter than ${MIN_ADMIN_PASSWORD_LENGTH} characters, which is weak. ` +
          "Use a long random password (e.g. `openssl rand -hex 24`), or leave ADMIN_PASSWORD unset to auto-generate " +
          "a strong 256-bit one. (The password value is not shown.)",
      );
    }
    return fromEnv;
  }
  const generated = randomBytes(32).toString("hex");
  log(
    "ADMIN_PASSWORD was not set. Generated a one-time admin password (shown ONCE — copy it now):\n" +
      `    ADMIN_PASSWORD=${generated}\n` +
      "Set ADMIN_PASSWORD in the environment to choose your own and silence this message.",
  );
  return generated;
}

/**
 * Start the admin HTTP server bound to 127.0.0.1:port. Returns the http.Server (already listening is
 * initiated; caller may attach further handlers). All routing/auth lives in the request handler below.
 */
export function startAdminServer(opts: AdminServerOptions): Server {
  const { store, secretStore, password, port, publicMcpUrl, log } = opts;

  const server = createServer((req, res) => {
    handle(req, res).catch((err) => {
      // Last-resort handler — never leak internals; log message only (never a secret).
      log("admin request error:", err instanceof Error ? err.message : String(err));
      if (!res.headersSent) sendJson(res, 500, { error: "Internal server error" });
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // ---- Anti DNS-rebinding / CSRF: Host must be loopback; Origin (if present) must be loopback. ----
    if (!hostHeaderIsLocal(req.headers.host)) {
      sendJson(res, 403, { error: "Forbidden: admin panel is reachable on localhost only." });
      return;
    }
    if (!originIsLocal(typeof req.headers.origin === "string" ? req.headers.origin : undefined)) {
      sendJson(res, 403, { error: "Forbidden: cross-origin request refused." });
      return;
    }

    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const path = url.pathname;

    // ---- Unauthenticated (but host-gated) surface: the HTML shell + a liveness probe. ----
    if (method === "GET" && path === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(ADMIN_HTML);
      return;
    }
    if (method === "GET" && path === "/healthz") {
      sendJson(res, 200, { ok: true });
      return;
    }

    // ---- Everything under /api requires the admin password (constant-time). ----
    if (path.startsWith("/api/")) {
      const presented = extractBearer(typeof req.headers.authorization === "string" ? req.headers.authorization : undefined);
      if (presented === undefined || !constantTimeEquals(presented, password)) {
        res.setHeader("WWW-Authenticate", "Bearer");
        sendJson(res, 401, { error: "Unauthorized: send 'Authorization: Bearer <ADMIN_PASSWORD>'." });
        return;
      }
      try {
        await dispatchApi(method, path, req, res);
      } catch (err) {
        if (err instanceof HttpError) {
          sendJson(res, err.status, { error: err.message });
        } else {
          const message = err instanceof Error ? err.message : String(err);
          sendJson(res, statusForStoreError(message), { error: message });
        }
      }
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  }

  async function dispatchApi(method: string, path: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
    // ---- Keys ----
    if (path === "/api/keys" && method === "GET") {
      sendJson(res, 200, store.listKeys().map(serializeKey));
      return;
    }
    if (path === "/api/keys" && method === "POST") {
      const body = await readJsonBody(req);
      const name = requireString(body, "name");
      const cloudflareToken = requireString(body, "cloudflare_token");
      const validate = body.validate === true;
      const { key, secretRef } = store.addKey(name);
      try {
        await secretStore.setSecret(secretRef, cloudflareToken);
      } catch (e) {
        // Roll back the orphaned metadata so a failed store leaves no dangling key.
        try {
          store.deleteKey(secretRef);
        } catch {
          /* best-effort rollback */
        }
        throw e;
      }
      const out: Record<string, unknown> = serializeKey(key);
      if (validate) out.validated = await probeCloudflareToken(cloudflareToken);
      log(`admin: created key '${name}' (${key.id})${validate ? ` validated=${(out.validated as { valid: boolean }).valid}` : ""}`);
      sendJson(res, 201, out);
      return;
    }
    const keyIdMatch = /^\/api\/keys\/([^/]+)$/.exec(path);
    if (keyIdMatch && method === "DELETE") {
      const id = decodeURIComponent(keyIdMatch[1]);
      store.deleteKey(id); // throws (→409) if still referenced by an agent
      await secretStore.deleteSecret(id);
      log(`admin: deleted key ${id}`);
      sendJson(res, 200, { ok: true });
      return;
    }

    // ---- Agents ----
    if (path === "/api/agents" && method === "GET") {
      const keyName = new Map(store.listKeys().map((k) => [k.id, k.name]));
      sendJson(res, 200, store.listAgents().map((a) => serializeAgent(a, keyName.get(a.key_id))));
      return;
    }
    if (path === "/api/agents" && method === "POST") {
      const body = await readJsonBody(req);
      const name = requireString(body, "name");
      const keyId = requireString(body, "key_id");
      const { agent, plaintextBearer } = store.createAgent(name, keyId);
      const keyName = store.listKeys().find((k) => k.id === agent.key_id)?.name;
      log(`admin: created agent '${name}' (${agent.id}) bound to key ${keyId}`); // never logs the bearer
      sendJson(res, 201, {
        ...serializeAgent(agent, keyName),
        bearer: plaintextBearer, // ONE-TIME — this is the only response that ever carries it
        connector_snippet: buildConnectorSnippet(name, plaintextBearer, publicMcpUrl),
      });
      return;
    }
    const agentRotate = /^\/api\/agents\/([^/]+)\/rotate$/.exec(path);
    if (agentRotate && method === "POST") {
      const id = decodeURIComponent(agentRotate[1]);
      const bearer = store.rotateBearer(id);
      const agent = store.listAgents().find((a) => a.id === id);
      const keyName = agent ? store.listKeys().find((k) => k.id === agent.key_id)?.name : undefined;
      log(`admin: rotated bearer for agent ${id}`); // never logs the bearer
      sendJson(res, 200, {
        bearer,
        connector_snippet: agent ? buildConnectorSnippet(agent.name, bearer, publicMcpUrl) : undefined,
      });
      return;
    }
    const agentIdMatch = /^\/api\/agents\/([^/]+)$/.exec(path);
    if (agentIdMatch && method === "PATCH") {
      const id = decodeURIComponent(agentIdMatch[1]);
      const body = await readJsonBody(req);
      let agent: Agent | undefined;
      if (Object.prototype.hasOwnProperty.call(body, "key_id")) {
        const keyId = requireString(body, "key_id");
        agent = store.rebindAgent(id, keyId);
      }
      if (Object.prototype.hasOwnProperty.call(body, "enabled")) {
        if (typeof body.enabled !== "boolean") throw new HttpError(400, "'enabled' must be a boolean.");
        agent = store.setAgentEnabled(id, body.enabled);
      }
      if (!agent) throw new HttpError(400, "PATCH requires at least one of 'enabled' or 'key_id'.");
      const keyName = store.listKeys().find((k) => k.id === agent!.key_id)?.name;
      log(`admin: patched agent ${id}`);
      sendJson(res, 200, serializeAgent(agent, keyName));
      return;
    }
    if (agentIdMatch && method === "DELETE") {
      const id = decodeURIComponent(agentIdMatch[1]);
      store.deleteAgent(id);
      log(`admin: deleted agent ${id}`);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 404, { error: "Not found." });
  }

  server.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      log(`ERROR: admin port ${port} is already in use. Set ADMIN_PORT to a free port.`);
    } else {
      log("ERROR: admin server failed:", err.message);
    }
    process.exit(1);
  });

  server.listen(port, ADMIN_BIND_HOST, () => {
    log(`admin panel on http://${ADMIN_BIND_HOST}:${port} (localhost only; password required)`);
  });

  return server;
}

// ====================================================================================
// The self-contained admin page. No external network / CDN — inline CSS + inline JS only.
// The client keeps the admin password in memory (a closure variable), prompted at login, and sends it
// as `Authorization: Bearer <password>` on every /api call. The page never persists the password.
// (Written without template literals / ${} so it can live safely inside this module's own template.)
// ====================================================================================
const ADMIN_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloudflare MCP Gateway — Admin</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 15px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #0f1115; color: #e6e8ec; }
  header { padding: 16px 24px; background: #171a21; border-bottom: 1px solid #2a2f3a; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 17px; margin: 0; font-weight: 600; }
  header .badge { font-size: 12px; color: #f6821f; border: 1px solid #f6821f55; padding: 2px 8px; border-radius: 999px; }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  section { background: #171a21; border: 1px solid #2a2f3a; border-radius: 10px; padding: 18px; margin-bottom: 22px; }
  section h2 { font-size: 15px; margin: 0 0 12px; font-weight: 600; letter-spacing: .01em; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #262b34; vertical-align: middle; }
  th { color: #97a0af; font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  td.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; color: #b9c1cc; }
  input, select, button { font: inherit; }
  input, select { background: #0f1115; color: #e6e8ec; border: 1px solid #2a2f3a; border-radius: 7px; padding: 8px 10px; }
  input:focus, select:focus { outline: none; border-color: #f6821f; }
  button { background: #f6821f; color: #141414; border: none; border-radius: 7px; padding: 8px 14px; font-weight: 600; cursor: pointer; }
  button.secondary { background: #262b34; color: #e6e8ec; }
  button.danger { background: #2b1416; color: #ff8f8f; border: 1px solid #5a2a2a; }
  button:hover { filter: brightness(1.08); }
  .row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
  .grow { flex: 1 1 180px; }
  .muted { color: #97a0af; font-size: 13px; }
  .actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .pill { font-size: 12px; padding: 2px 8px; border-radius: 999px; }
  .pill.on { background: #12331f; color: #64d98a; }
  .pill.off { background: #3a1e12; color: #f0a35e; }
  .empty { color: #6b7482; font-style: italic; padding: 8px 10px; }
  .banner { background: #10261a; border: 1px solid #1f5a38; border-radius: 8px; padding: 14px; margin-bottom: 16px; }
  .banner h3 { margin: 0 0 8px; font-size: 14px; color: #64d98a; }
  .banner pre { background: #0b0d11; border: 1px solid #2a2f3a; border-radius: 6px; padding: 10px; overflow: auto; font-size: 12px; color: #cfd6df; white-space: pre-wrap; word-break: break-all; }
  .err { color: #ff8f8f; font-size: 13px; margin: 8px 0; min-height: 18px; }
  #login { max-width: 380px; margin: 80px auto; }
  label { display: block; font-size: 12px; color: #97a0af; margin: 10px 0 4px; }
  .hide { display: none; }
</style>
</head>
<body>
<div id="login">
  <section>
    <h2>Gateway Admin</h2>
    <p class="muted">Enter the admin password (ADMIN_PASSWORD). It is held in this tab's memory only and never stored.</p>
    <label for="pw">Admin password</label>
    <input id="pw" type="password" autocomplete="current-password" style="width:100%">
    <div class="err" id="loginErr"></div>
    <button id="loginBtn" style="width:100%">Unlock</button>
  </section>
</div>

<div id="app" class="hide">
  <header>
    <h1>Cloudflare MCP Gateway</h1>
    <span class="badge">admin · localhost</span>
    <span class="grow"></span>
    <button class="secondary" id="lockBtn">Lock</button>
  </header>
  <main>
    <div id="banner"></div>
    <div class="err" id="appErr"></div>

    <section>
      <h2>Keys <span class="muted">— a named Cloudflare token, stored encrypted at rest</span></h2>
      <table><thead><tr><th>Name</th><th>ID</th><th>Created</th><th></th></tr></thead>
        <tbody id="keysBody"></tbody></table>
      <div style="margin-top:14px" class="row">
        <input id="keyName" class="grow" placeholder="Key name (e.g. acme-prod)">
        <input id="keyToken" class="grow" type="password" placeholder="Cloudflare API token (scoped)">
        <label style="display:flex;gap:6px;align-items:center;margin:0"><input id="keyValidate" type="checkbox"> validate</label>
        <button id="addKeyBtn">Add key</button>
      </div>
    </section>

    <section>
      <h2>Agents <span class="muted">— a bearer-authenticated caller bound to one key</span></h2>
      <table><thead><tr><th>Name</th><th>Key</th><th>Status</th><th>ID</th><th></th></tr></thead>
        <tbody id="agentsBody"></tbody></table>
      <div style="margin-top:14px" class="row">
        <input id="agentName" class="grow" placeholder="Agent name (e.g. claude-desktop)">
        <select id="agentKey" class="grow"></select>
        <button id="addAgentBtn">Create agent</button>
      </div>
    </section>
  </main>
</div>

<script>
(function () {
  var pw = null;
  var keysCache = [];

  function $(id) { return document.getElementById(id); }
  function show(id, on) { $(id).classList.toggle("hide", !on); }
  function setErr(id, msg) { $(id).textContent = msg || ""; }

  function api(method, path, body) {
    var opts = { method: method, headers: { "Authorization": "Bearer " + pw } };
    if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    return fetch(path, opts).then(function (r) {
      if (r.status === 401) { lock(); throw new Error("Unauthorized — re-enter the admin password."); }
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
        return data;
      });
    });
  }

  function esc(s) { return String(s == null ? "" : s); }
  function cell(text, cls) { var td = document.createElement("td"); if (cls) td.className = cls; td.textContent = esc(text); return td; }

  function shortDate(iso) { try { return new Date(iso).toLocaleString(); } catch (e) { return esc(iso); } }

  function renderKeys(keys) {
    keysCache = keys;
    var body = $("keysBody"); body.textContent = "";
    if (!keys.length) { var tr = document.createElement("tr"); var td = cell("No keys yet.", "empty"); td.colSpan = 4; tr.appendChild(td); body.appendChild(tr); }
    keys.forEach(function (k) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(k.name));
      tr.appendChild(cell(k.id, "mono"));
      tr.appendChild(cell(shortDate(k.created_at), "muted"));
      var act = document.createElement("td");
      var del = document.createElement("button"); del.className = "danger"; del.textContent = "Delete";
      del.onclick = function () {
        if (!confirm("Delete key '" + k.name + "'? Refused if an agent still uses it.")) return;
        api("DELETE", "/api/keys/" + encodeURIComponent(k.id)).then(refresh).catch(function (e) { setErr("appErr", e.message); });
      };
      act.appendChild(del); tr.appendChild(act);
      body.appendChild(tr);
    });
    // refresh the agent-key <select>
    var sel = $("agentKey"); sel.textContent = "";
    if (!keys.length) { var o = document.createElement("option"); o.textContent = "— add a key first —"; o.value = ""; sel.appendChild(o); }
    keys.forEach(function (k) { var o = document.createElement("option"); o.value = k.id; o.textContent = k.name; sel.appendChild(o); });
  }

  function renderAgents(agents) {
    var body = $("agentsBody"); body.textContent = "";
    if (!agents.length) { var tr = document.createElement("tr"); var td = cell("No agents yet.", "empty"); td.colSpan = 5; tr.appendChild(td); body.appendChild(tr); }
    agents.forEach(function (a) {
      var tr = document.createElement("tr");
      tr.appendChild(cell(a.name));
      // key select (rebind)
      var ktd = document.createElement("td");
      var ksel = document.createElement("select");
      keysCache.forEach(function (k) { var o = document.createElement("option"); o.value = k.id; o.textContent = k.name; if (k.id === a.key_id) o.selected = true; ksel.appendChild(o); });
      ksel.onchange = function () { api("PATCH", "/api/agents/" + encodeURIComponent(a.id), { key_id: ksel.value }).then(refresh).catch(function (e) { setErr("appErr", e.message); }); };
      ktd.appendChild(ksel); tr.appendChild(ktd);
      // status
      var std = document.createElement("td");
      var pill = document.createElement("span"); pill.className = "pill " + (a.enabled ? "on" : "off"); pill.textContent = a.enabled ? "enabled" : "disabled";
      std.appendChild(pill); tr.appendChild(std);
      tr.appendChild(cell(a.id, "mono"));
      // actions
      var act = document.createElement("td"); act.className = "actions";
      var toggle = document.createElement("button"); toggle.className = "secondary"; toggle.textContent = a.enabled ? "Disable" : "Enable";
      toggle.onclick = function () { api("PATCH", "/api/agents/" + encodeURIComponent(a.id), { enabled: !a.enabled }).then(refresh).catch(function (e) { setErr("appErr", e.message); }); };
      var rot = document.createElement("button"); rot.className = "secondary"; rot.textContent = "Rotate";
      rot.onclick = function () {
        if (!confirm("Rotate bearer for '" + a.name + "'? The current bearer stops working immediately.")) return;
        api("POST", "/api/agents/" + encodeURIComponent(a.id) + "/rotate").then(function (d) { showBearer(a.name, d.bearer, d.connector_snippet); refresh(); }).catch(function (e) { setErr("appErr", e.message); });
      };
      var del = document.createElement("button"); del.className = "danger"; del.textContent = "Delete";
      del.onclick = function () { if (!confirm("Delete agent '" + a.name + "'?")) return; api("DELETE", "/api/agents/" + encodeURIComponent(a.id)).then(refresh).catch(function (e) { setErr("appErr", e.message); }); };
      act.appendChild(toggle); act.appendChild(rot); act.appendChild(del); tr.appendChild(act);
      body.appendChild(tr);
    });
  }

  function showBearer(name, bearer, snippet) {
    var b = $("banner");
    var wrap = document.createElement("div"); wrap.className = "banner";
    var h = document.createElement("h3"); h.textContent = "Bearer for '" + name + "' — shown once. Copy it now.";
    var p1 = document.createElement("pre"); p1.textContent = bearer;
    wrap.appendChild(h); wrap.appendChild(p1);
    if (snippet) {
      var lbl = document.createElement("div"); lbl.className = "muted"; lbl.style.margin = "10px 0 4px"; lbl.textContent = "Connector config (paste into your MCP client; replace the host if it is a placeholder):";
      var p2 = document.createElement("pre"); p2.textContent = snippet;
      wrap.appendChild(lbl); wrap.appendChild(p2);
    }
    var dismiss = document.createElement("button"); dismiss.className = "secondary"; dismiss.style.marginTop = "10px"; dismiss.textContent = "Dismiss";
    dismiss.onclick = function () { b.textContent = ""; };
    wrap.appendChild(dismiss);
    b.textContent = ""; b.appendChild(wrap);
    window.scrollTo(0, 0);
  }

  function refresh() {
    setErr("appErr", "");
    return Promise.all([api("GET", "/api/keys"), api("GET", "/api/agents")]).then(function (r) {
      renderKeys(r[0]); renderAgents(r[1]);
    }).catch(function (e) { setErr("appErr", e.message); });
  }

  function unlock() {
    var val = $("pw").value;
    if (!val) { setErr("loginErr", "Enter the admin password."); return; }
    pw = val;
    // Probe with a real request so a wrong password is caught immediately.
    api("GET", "/api/keys").then(function (keys) {
      $("pw").value = ""; setErr("loginErr", "");
      show("login", false); show("app", true);
      renderKeys(keys); return api("GET", "/api/agents").then(renderAgents);
    }).catch(function (e) { pw = null; setErr("loginErr", e.message); });
  }

  function lock() { pw = null; show("app", false); show("login", true); $("banner").textContent = ""; }

  $("loginBtn").onclick = unlock;
  $("pw").addEventListener("keydown", function (e) { if (e.key === "Enter") unlock(); });
  $("lockBtn").onclick = lock;

  $("addKeyBtn").onclick = function () {
    var name = $("keyName").value.trim(); var token = $("keyToken").value; var validate = $("keyValidate").checked;
    if (!name || !token) { setErr("appErr", "Key name and token are both required."); return; }
    api("POST", "/api/keys", { name: name, cloudflare_token: token, validate: validate }).then(function (d) {
      $("keyName").value = ""; $("keyToken").value = "";
      if (d.validated) setErr("appErr", "Key added. Token validation: " + (d.validated.valid ? "VALID" : "INVALID") + " (" + d.validated.detail + ")");
      return refresh();
    }).catch(function (e) { setErr("appErr", e.message); });
  };

  $("addAgentBtn").onclick = function () {
    var name = $("agentName").value.trim(); var keyId = $("agentKey").value;
    if (!name) { setErr("appErr", "Agent name is required."); return; }
    if (!keyId) { setErr("appErr", "Create a key first, then bind the agent to it."); return; }
    api("POST", "/api/agents", { name: name, key_id: keyId }).then(function (d) {
      $("agentName").value = "";
      showBearer(d.name, d.bearer, d.connector_snippet);
      return refresh();
    }).catch(function (e) { setErr("appErr", e.message); });
  };
})();
</script>
</body>
</html>`;
