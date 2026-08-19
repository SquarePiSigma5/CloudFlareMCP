/**
 * Shared Cloudflare API client for the MCP server.
 * Auth: CLOUDFLARE_API_TOKEN env var (scoped token, never the Global API Key).
 */

const API_BASE = "https://api.cloudflare.com/client/v4";
const API_BASE_URL = new URL(API_BASE);
/** Fixed origin every request is pinned to. */
const API_ORIGIN = API_BASE_URL.origin; // "https://api.cloudflare.com"
/** Every request pathname must live under this prefix (note the trailing slash). */
const API_PATH_PREFIX = `${API_BASE_URL.pathname}/`; // "/client/v4/"

/** Truncate any single tool response body beyond this many characters. */
export const CHARACTER_LIMIT = 25_000;

export interface CfError {
  code: number;
  message: string;
}

export interface ResultInfo {
  page: number;
  per_page: number;
  count: number;
  total_count: number;
  total_pages?: number;
}

export interface CfEnvelope<T> {
  success: boolean;
  errors: CfError[];
  messages: unknown[];
  result: T;
  result_info?: ResultInfo;
}

export interface Zone {
  id: string;
  name: string;
  status: string;
  paused?: boolean;
}

export interface DnsRecord {
  id: string;
  type: string;
  name: string;
  content?: string;
  ttl: number;
  proxied?: boolean;
  priority?: number;
  comment?: string | null;
  data?: Record<string, unknown>;
  created_on?: string;
  modified_on?: string;
}

/** Slimmed record shape returned to the model (keeps context small). */
export interface SlimRecord {
  id: string;
  type: string;
  name: string;
  content?: string;
  ttl: number;
  proxied?: boolean;
  priority?: number;
  comment?: string;
  data?: Record<string, unknown>;
  modified_on?: string;
}

export class CloudflareApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly errors?: CfError[],
  ) {
    super(message);
    this.name = "CloudflareApiError";
  }
}

function apiToken(): string {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!token) {
    throw new CloudflareApiError(
      "CLOUDFLARE_API_TOKEN is not set in the server's environment. Create a scoped token " +
        "(template: 'Edit zone DNS', limited to the zones you manage) at " +
        "https://dash.cloudflare.com/profile/api-tokens and restart the server with it set.",
    );
  }
  return token;
}

interface RequestOptions {
  query?: Record<string, string | number | undefined>;
  body?: unknown;
}

/**
 * Validate a caller-supplied, RELATIVE Cloudflare v4 API path and return the pinned request URL.
 *
 * This is the single source of truth for how a path becomes a URL — doFetch() calls it too, so the
 * URL that is actually fetched is exactly the one that was validated (there is no second,
 * drift-prone construction that a future refactor could let diverge from the check).
 *
 * Host pinning holds because the origin is fixed by the literal API_BASE prefix BEFORE new URL()
 * ever parses the caller's path: the URL is always built with `new URL(`${API_BASE}${path}`)` by
 * string concatenation, NEVER the two-argument `new URL(path, API_BASE)` form — in that form an
 * absolute URL in `path` (e.g. "https://evil.example/x") would replace the base entirely and send
 * the Cloudflare bearer token to another host. The origin/pathname assertions below are a
 * defense-in-depth backstop against that invariant being broken later; they are NOT a redirect
 * safeguard (a cross-origin redirect from Cloudflare's own server is out of scope, and fetch drops
 * credentials across origins regardless).
 */
export function validateApiPath(path: string): URL {
  if (typeof path !== "string" || path.length === 0) {
    throw new CloudflareApiError("API path is required, e.g. '/zones' or '/zones/{zone_id}/purge_cache'.");
  }
  if (!path.startsWith("/")) {
    throw new CloudflareApiError(
      `API path must be relative to the Cloudflare v4 base and begin with '/' (got ${JSON.stringify(path)}). ` +
        "Pass a path like '/zones' — not a full URL, host, or scheme.",
    );
  }
  if (path.startsWith("//")) {
    throw new CloudflareApiError(
      `API path must not begin with '//' (got ${JSON.stringify(path)}) — a protocol-relative path could target another host.`,
    );
  }
  if (path.includes("\\")) {
    throw new CloudflareApiError(`API path must not contain a backslash (got ${JSON.stringify(path)}).`);
  }
  if (/[\s\u0000-\u001f\u007f]/.test(path)) {
    throw new CloudflareApiError("API path must not contain whitespace or control characters.");
  }
  // Any '..' segment can walk out of /client/v4; reject up front (the pathname check below is the backstop).
  if (path.split(/[/?#]/).includes("..")) {
    throw new CloudflareApiError(`API path must not contain '..' path traversal (got ${JSON.stringify(path)}).`);
  }
  let url: URL;
  try {
    // String concatenation only — see the doc comment above for why the two-arg form is unsafe.
    url = new URL(`${API_BASE}${path}`);
  } catch {
    throw new CloudflareApiError(`API path is not a valid URL path (got ${JSON.stringify(path)}).`);
  }
  if (url.origin !== API_ORIGIN || !url.pathname.startsWith(API_PATH_PREFIX)) {
    throw new CloudflareApiError(
      `API path must resolve under ${API_ORIGIN}${API_PATH_PREFIX} (got ${JSON.stringify(path)}). ` +
        "Absolute URLs, other hosts, userinfo, and paths that escape the v4 base are refused.",
    );
  }
  return url;
}

async function doFetch(method: string, path: string, opts: RequestOptions): Promise<Response> {
  // Single, pinned URL construction (host-pinning + SSRF guard) shared with the passthrough validator.
  const url = validateApiPath(path);
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  }
  try {
    return await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${apiToken()}`,
        ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new CloudflareApiError(
      `Network error reaching the Cloudflare API (${reason}). ` +
        "Check the machine running this MCP server has outbound HTTPS access to api.cloudflare.com, then retry.",
    );
  }
}

/** True when an error (or its cause) is an abort/timeout from the request's AbortSignal. */
function isAbortError(err: unknown): boolean {
  if (err instanceof Error) {
    if (err.name === "AbortError" || err.name === "TimeoutError") return true;
    const cause = (err as { cause?: unknown }).cause;
    if (cause instanceof Error && (cause.name === "AbortError" || cause.name === "TimeoutError")) return true;
  }
  return false;
}

/** CloudflareApiError for an abort/timeout that fired while the response body was being read. */
function bodyReadTimeoutError(): CloudflareApiError {
  return new CloudflareApiError(
    "Network error reaching the Cloudflare API (the request timed out while reading the response body). " +
      "Check the machine running this MCP server has outbound HTTPS access to api.cloudflare.com, then retry.",
  );
}

function statusHint(status: number, errors: CfError[]): string {
  const codes = errors.map((e) => e.code);
  if (status === 401 || codes.includes(10000)) {
    return " The API token is missing, invalid, or expired — verify CLOUDFLARE_API_TOKEN.";
  }
  if (status === 403) {
    return " The API token likely lacks permission for this zone or action (needs Zone → DNS → Edit on the target zone).";
  }
  if (status === 404) {
    return " The zone or record was not found — re-check IDs with cloudflare_list_zones / cloudflare_list_dns_records.";
  }
  if (status === 429) {
    return " Rate limited by Cloudflare — wait a moment and retry.";
  }
  return "";
}

/** JSON request against the Cloudflare v4 API with envelope + error handling. */
export async function cfRequest<T>(method: string, path: string, opts: RequestOptions = {}): Promise<CfEnvelope<T>> {
  const res = await doFetch(method, path, opts);
  let payload: CfEnvelope<T>;
  try {
    payload = (await res.json()) as CfEnvelope<T>;
  } catch (err) {
    if (isAbortError(err)) throw bodyReadTimeoutError();
    throw new CloudflareApiError(
      `Cloudflare returned a non-JSON response (HTTP ${res.status}). ` +
        "A proxy or firewall between this server and api.cloudflare.com may be intercepting the request.",
      res.status,
    );
  }
  if (!res.ok || !payload.success) {
    const errors = payload.errors ?? [];
    const details = errors.map((e) => `[${e.code}] ${e.message}`).join("; ") || `HTTP ${res.status}`;
    throw new CloudflareApiError(`Cloudflare API error: ${details}.${statusHint(res.status, errors)}`, res.status, errors);
  }
  return payload;
}

/** Plain-text request (used for the BIND zone-file export endpoint). */
export async function cfRequestText(method: string, path: string): Promise<string> {
  const res = await doFetch(method, path, {});
  let text: string;
  try {
    text = await res.text();
  } catch (err) {
    if (isAbortError(err)) throw bodyReadTimeoutError();
    throw err;
  }
  if (!res.ok) {
    // Export errors still come back as the JSON envelope.
    try {
      const payload = JSON.parse(text) as CfEnvelope<unknown>;
      const errors = payload.errors ?? [];
      const details = errors.map((e) => `[${e.code}] ${e.message}`).join("; ") || `HTTP ${res.status}`;
      throw new CloudflareApiError(`Cloudflare API error: ${details}.${statusHint(res.status, errors)}`, res.status, errors);
    } catch (err) {
      if (err instanceof CloudflareApiError) throw err;
      throw new CloudflareApiError(`Cloudflare API error (HTTP ${res.status}): ${text.slice(0, 300)}`, res.status);
    }
  }
  return text;
}

/** Outcome of a guarded raw passthrough request. Exactly one body field is set on success. */
export interface PassthroughResponse {
  status: number;
  ok: boolean;
  /** Parsed JSON body, when the response was JSON. */
  json?: unknown;
  /** Raw text body, when the response was a successful non-JSON payload (e.g. a BIND export). */
  text?: string;
  /** True when the body was returned as raw text rather than parsed JSON. */
  nonJson?: boolean;
}

/**
 * Guarded raw request for the cloudflare_api_request passthrough tool.
 *
 * It reuses doFetch (so the Authorization header is still added centrally — the token never leaks
 * here — and the path is host-pinned by validateApiPath) and statusHint (so error rendering matches
 * the DNS tools). Unlike cfRequest it does NOT assume the standard {success, result} envelope: the
 * wider v4 API returns bare JSON, non-JSON text (BIND exports, PEM, Worker source), and empty bodies
 * (HEAD), so a successful non-JSON 200 must not be misreported as a "proxy is intercepting" failure.
 * HEAD is handled without reading a body at all (which is exactly why it cannot reuse cfRequest,
 * whose unconditional res.json() throws on the empty body every HEAD returns).
 */
export async function cfApiPassthrough(method: string, path: string, opts: RequestOptions = {}): Promise<PassthroughResponse> {
  const res = await doFetch(method, path, opts);

  if (method === "HEAD") {
    // HEAD has no body by definition — report the HTTP outcome, never parse a body.
    if (!res.ok) {
      throw new CloudflareApiError(`Cloudflare API error (HTTP ${res.status}).${statusHint(res.status, [])}`, res.status);
    }
    return { status: res.status, ok: res.ok };
  }

  let bodyText: string;
  try {
    bodyText = await res.text();
  } catch (err) {
    if (isAbortError(err)) throw bodyReadTimeoutError();
    throw err;
  }

  const contentType = res.headers.get("content-type") ?? "";
  const looksJson = /\bjson\b/i.test(contentType) || /^\s*[[{]/.test(bodyText);

  if (bodyText.trim().length > 0 && looksJson) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      throw new CloudflareApiError(`Cloudflare returned a malformed JSON response (HTTP ${res.status}).`, res.status);
    }
    // Surface the standard envelope's errors when present; otherwise return the JSON as-is.
    const env = parsed as { success?: boolean; errors?: CfError[] };
    if (!res.ok || env.success === false) {
      const errors = env.errors ?? [];
      const details = errors.map((e) => `[${e.code}] ${e.message}`).join("; ") || `HTTP ${res.status}`;
      throw new CloudflareApiError(`Cloudflare API error: ${details}.${statusHint(res.status, errors)}`, res.status, errors);
    }
    return { status: res.status, ok: res.ok, json: parsed };
  }

  // Non-JSON (or empty) body.
  if (!res.ok) {
    const detail = bodyText ? `: ${bodyText.slice(0, 300)}` : "";
    throw new CloudflareApiError(`Cloudflare API error (HTTP ${res.status})${detail}.${statusHint(res.status, [])}`, res.status);
  }
  return { status: res.status, ok: res.ok, text: bodyText, nonJson: true };
}

const ZONE_ID_RE = /^[0-9a-f]{32}$/;
const zoneCache = new Map<string, Zone>();

/** Normalize a zone reference (name or ID) into its cache key: trimmed, lowercased, no trailing dot. */
function normalizeZoneKey(zone: string): string {
  return zone.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Resolve a zone given either its domain name ("example.com") or its 32-char zone ID.
 * Caches results for the lifetime of the process.
 */
export async function resolveZone(zone: string): Promise<Zone> {
  const key = normalizeZoneKey(zone);
  if (!key) {
    throw new CloudflareApiError("Empty zone. Pass a domain name (e.g. 'example.com') or a 32-character zone ID.");
  }
  const cached = zoneCache.get(key);
  if (cached) return cached;

  if (ZONE_ID_RE.test(key)) {
    const { result } = await cfRequest<Zone>("GET", `/zones/${key}`);
    zoneCache.set(result.id, result);
    zoneCache.set(result.name.toLowerCase(), result);
    return result;
  }

  const { result } = await cfRequest<Zone[]>("GET", "/zones", { query: { name: key, per_page: 5 } });
  if (result.length === 0) {
    const all = await cfRequest<Zone[]>("GET", "/zones", { query: { per_page: 50 } });
    const names = all.result.map((z) => z.name).join(", ") || "(none visible to this token)";
    throw new CloudflareApiError(
      `No zone named '${key}' is accessible with this API token. Zones this token can see: ${names}. ` +
        "Pass one of those names, or widen the token's zone scope in the Cloudflare dashboard.",
    );
  }
  const found = result[0];
  zoneCache.set(found.id, found);
  zoneCache.set(found.name.toLowerCase(), found);
  return found;
}

/**
 * Run `fn` against a resolved zone, recovering transparently from a stale zone cache.
 *
 * zoneCache lives for the whole process, so a zone that was deleted and re-created under a
 * new ID would otherwise keep resolving to the dead cached ID forever. When `fn` fails with a
 * 404 on a zone we served from cache, that cached ID is the prime suspect: evict it, re-resolve
 * the reference fresh, and — only if the zone truly moved to a new ID — retry `fn` once against
 * the new zone. A 404 whose re-resolved ID is unchanged is about the record, not the zone, so
 * the original error is rethrown without re-running `fn`.
 */
export async function withZone<T>(zoneRef: string, fn: (zone: Zone) => Promise<T>): Promise<T> {
  const key = normalizeZoneKey(zoneRef);
  const wasCached = zoneCache.has(key);
  const zone = await resolveZone(zoneRef);
  try {
    return await fn(zone);
  } catch (err) {
    if (err instanceof CloudflareApiError && err.status === 404 && wasCached) {
      zoneCache.delete(zone.id);
      zoneCache.delete(zone.name.toLowerCase());
      const fresh = await resolveZone(zoneRef);
      if (fresh.id === zone.id) {
        // Zone is unchanged — the 404 was about the record, not the cached zone. Rethrow as-is.
        throw err;
      }
      // Zone was re-created under a new ID; retry once (a second failure propagates).
      return await fn(fresh);
    }
    throw err;
  }
}

export function slimRecord(r: DnsRecord): SlimRecord {
  return {
    id: r.id,
    type: r.type,
    name: r.name,
    ...(r.content !== undefined ? { content: r.content } : {}),
    ttl: r.ttl,
    ...(r.proxied !== undefined ? { proxied: r.proxied } : {}),
    ...(r.priority !== undefined ? { priority: r.priority } : {}),
    ...(r.comment ? { comment: r.comment } : {}),
    ...(r.data !== undefined ? { data: r.data } : {}),
    ...(r.modified_on ? { modified_on: r.modified_on } : {}),
  };
}

export function formatTtl(ttl: number): string {
  return ttl === 1 ? "Auto" : `${ttl}s`;
}

export function formatRecordLine(r: SlimRecord): string {
  const flags: string[] = [`ttl ${formatTtl(r.ttl)}`];
  if (r.proxied) flags.push("proxied");
  if (r.priority !== undefined) flags.push(`priority ${r.priority}`);
  const content = r.content ?? (r.data ? JSON.stringify(r.data) : "(no content)");
  const comment = r.comment ? `  # ${r.comment}` : "";
  return `- ${r.type} ${r.name} → ${content} (${flags.join(", ")}) [id: ${r.id}]${comment}`;
}

export function truncate(text: string, hint = "use filters (type/name) or pagination to narrow the result"): string {
  if (text.length <= CHARACTER_LIMIT) return text;
  return text.slice(0, CHARACTER_LIMIT) + `\n… [truncated at ${CHARACTER_LIMIT} characters — ${hint}]`;
}
