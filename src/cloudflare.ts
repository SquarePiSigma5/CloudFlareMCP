/**
 * Shared Cloudflare API client for the MCP server.
 * Auth: CLOUDFLARE_API_TOKEN env var (scoped token, never the Global API Key).
 */

const API_BASE = "https://api.cloudflare.com/client/v4";

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

async function doFetch(method: string, path: string, opts: RequestOptions): Promise<Response> {
  const url = new URL(`${API_BASE}${path}`);
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

const ZONE_ID_RE = /^[0-9a-f]{32}$/;
const zoneCache = new Map<string, Zone>();

/**
 * Resolve a zone given either its domain name ("example.com") or its 32-char zone ID.
 * Caches results for the lifetime of the process.
 */
export async function resolveZone(zone: string): Promise<Zone> {
  const key = zone.trim().toLowerCase().replace(/\.$/, "");
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
