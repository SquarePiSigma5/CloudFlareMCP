import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  CloudflareApiError,
  DnsRecord,
  SlimRecord,
  Zone,
  buildWorkerUploadPlan,
  cfApiPassthrough,
  cfRequest,
  cfRequestForm,
  cfRequestText,
  formatRecordLine,
  resolveAccountId,
  slimRecord,
  truncate,
  validateApiPath,
  withZone,
} from "./cloudflare.js";

/** All DNS record types Cloudflare accepts via the API. */
const RECORD_TYPES = [
  "A",
  "AAAA",
  "CAA",
  "CERT",
  "CNAME",
  "DNSKEY",
  "DS",
  "HTTPS",
  "LOC",
  "MX",
  "NAPTR",
  "NS",
  "OPENPGPKEY",
  "PTR",
  "SMIMEA",
  "SRV",
  "SSHFP",
  "SVCB",
  "TLSA",
  "TXT",
  "URI",
] as const;

const PROXYABLE_TYPES = new Set(["A", "AAAA", "CNAME"]);

/** HTTP methods the raw passthrough accepts. GET/HEAD are reads; the rest are writes. */
const PASSTHROUGH_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
const MUTATING_METHODS = new Set<string>(["POST", "PUT", "PATCH", "DELETE"]);

/** Passthrough permission modes, resolved from CLOUDFLARE_API_PASSTHROUGH at call time. */
type PassthroughMode = "off" | "read" | "full";

/**
 * Resolve the passthrough mode from the raw env value.
 *
 * Reads-on by default: unset/undefined, "read", an empty or whitespace-padded string, and any
 * unrecognized or mistyped value all resolve to "read" (GET/HEAD passthrough). An EXACT "off"
 * disables the tool entirely; an EXACT "full" additionally enables writes (each still requiring
 * confirm=true). Only an exact "full" ever yields write access: the "full" comparison runs BEFORE
 * any trimming, so a mistyped value like "Full", "FULL ", " full", or "fulll" degrades to
 * reads-only ("read"), NEVER "full" — a typo can therefore never widen to write access.
 * Note that even "read" exposes every GET/HEAD endpoint the token can reach, not just DNS.
 */
export function resolvePassthroughMode(raw: string | undefined): PassthroughMode {
  if (raw === "off") return "off";
  if (raw === "full") return "full";
  // Unset, "read", or any other value → reads-only default. Writes require an EXACT "full",
  // so a mistyped value can never widen to write access.
  return "read";
}

// ====================================================================
// Workers tools (#10 set-secret-from-env, #11 deploy) — operator gates.
//
// These live behind their own env-var opt-ins, mirroring the passthrough's "operator switch +
// per-call confirm" model. NONE of them is enabled by simply deploying the server:
//   - CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST   which server env var NAMES may become secrets
//   - CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST which Worker script NAMES may receive a secret
//   - CLOUDFLARE_WORKERS_DEPLOY_ENABLE=true     lets cloudflare_deploy_worker run at all
// All matching is EXACT-STRING and CASE-SENSITIVE (POSIX env-var and Cloudflare script names are
// case-sensitive); the only normalization is trimming list entries.
// ====================================================================

/**
 * Env var names that must NEVER be exposable as a Worker secret, even if an operator mistakenly adds
 * one to the allowlist. These are the server's own trust boundary (the Cloudflare token, the MCP
 * bearer token, the unauthenticated-bind override) — leaking any of them defeats the whole model.
 */
export const WORKER_SECRET_ENV_DENYLIST: readonly string[] = ["CLOUDFLARE_API_TOKEN", "MCP_AUTH_TOKEN", "ALLOW_UNAUTHENTICATED"];

/** Parse a comma-separated allowlist env value into trimmed, non-empty names (order-preserving). */
export function parseEnvAllowlist(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Outcome of deciding whether one env var may be read as a Worker secret. */
export type EnvVarAccess = { ok: true } | { ok: false; reason: "disabled" | "denylisted" | "not-allowlisted" };

/**
 * PURE decision for whether `envVar` may be read from the server environment as a Worker secret.
 *
 * Precedence (fail-closed): an EMPTY allowlist disables the feature entirely ("disabled"); a
 * denylisted name is refused even when it also appears in the allowlist ("denylisted"); otherwise the
 * name must be an EXACT, case-sensitive member of the allowlist ("not-allowlisted" if absent).
 * No process.env is read here — the caller passes the raw allowlist string — so it is unit-testable.
 */
export function resolveEnvVarAccess(envVar: string, allowlistRaw: string | undefined): EnvVarAccess {
  const allowlist = parseEnvAllowlist(allowlistRaw);
  if (allowlist.length === 0) return { ok: false, reason: "disabled" };
  if (WORKER_SECRET_ENV_DENYLIST.includes(envVar)) return { ok: false, reason: "denylisted" };
  if (!allowlist.includes(envVar)) return { ok: false, reason: "not-allowlisted" };
  return { ok: true };
}

/** Parse the script-name allowlist env value into trimmed, non-empty Worker script names. */
export function parseScriptAllowlist(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * PURE check: may a Worker secret be set on `scriptName`? Fail-closed — an EMPTY allowlist permits NO
 * script (so a model-deployed script can never receive an allowlisted secret), and membership is an
 * EXACT, case-sensitive match. The caller passes the raw allowlist string, so this is unit-testable.
 */
export function isScriptAllowedForSecret(scriptName: string, allowlistRaw: string | undefined): boolean {
  const allow = parseScriptAllowlist(allowlistRaw);
  return allow.length > 0 && allow.includes(scriptName);
}

/**
 * PURE gate for cloudflare_deploy_worker. Fail-closed and strict: only an EXACT "true" enables Worker
 * deploys, so a typo or wrong case ("TRUE", " true", "1") leaves the tool disabled — a mistake can
 * never widen to enabling arbitrary code deployment.
 */
export function isWorkersDeployEnabled(raw: string | undefined): boolean {
  return raw === "true";
}

/** Cloudflare Worker script name: a single path segment, letters/digits/underscore/hyphen. */
const WORKER_SCRIPT_NAME_RE = /^[A-Za-z0-9_-]{1,63}$/;
/** Worker secret / binding name: a valid environment binding identifier (accessed as env.NAME). */
const WORKER_SECRET_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
/** Server env-var name to read: standard POSIX-style identifier. */
const ENV_VAR_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** Module/body part filename (may carry an extension, e.g. worker.mjs). */
const MODULE_NAME_RE = /^[A-Za-z0-9_.-]{1,128}$/;

const scriptNameParam = z
  .string()
  .regex(WORKER_SCRIPT_NAME_RE, "Worker script name must be 1-63 chars of letters, digits, '_' or '-'.")
  .describe("Cloudflare Worker script name (letters, digits, '_' or '-'). This is a single path segment.");

const accountIdParam = z
  .string()
  .regex(/^[0-9a-fA-F]{32}$/, "account_id must be a 32-character hex Cloudflare account ID.")
  .describe("Cloudflare account ID (32-char hex). Optional — falls back to CLOUDFLARE_ACCOUNT_ID or the token's sole account.");

const zoneParam = z
  .string()
  .min(1)
  .describe("Zone domain name (e.g. 'example.com') or its 32-character zone ID. Use cloudflare_list_zones to discover zones.");

const recordIdParam = z
  .string()
  .min(1)
  .describe("DNS record ID (32-char hex), as returned by cloudflare_list_dns_records or cloudflare_create_dns_record.");

const ttlParam = z
  .number()
  .int()
  .refine((v) => v === 1 || (v >= 30 && v <= 86_400), {
    message:
      "TTL must be 1 (meaning 'Auto') or between 30 and 86400 seconds. Note: TTLs of 30–59 are accepted only on Cloudflare Enterprise zones; the floor is 60 seconds on all other plans.",
  })
  .describe(
    "Time-to-live in seconds. Use 1 for 'Auto' (default). Otherwise 30–86400 — but TTLs of 30–59 are accepted only on Cloudflare Enterprise zones; the floor is 60 seconds elsewhere.",
  );

type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

function ok(text: string, structured?: Record<string, unknown>, hint?: string): ToolResult {
  return {
    content: [{ type: "text", text: hint !== undefined ? truncate(text, hint) : truncate(text) }],
    ...(structured ? { structuredContent: structured } : {}),
  };
}

function fail(err: unknown): ToolResult {
  const message =
    err instanceof CloudflareApiError
      ? err.message
      : err instanceof Error
        ? `Unexpected error: ${err.message}`
        : `Unexpected error: ${String(err)}`;
  // Neutral hint — narrowing filters don't apply to an error message.
  return { isError: true, content: [{ type: "text", text: truncate(`Error: ${message}`, "the remainder of the error message was omitted") }] };
}

async function getRecord(zone: Zone, recordId: string): Promise<DnsRecord> {
  const { result } = await cfRequest<DnsRecord>("GET", `/zones/${zone.id}/dns_records/${recordId}`);
  return result;
}

/**
 * Defense-in-depth for cloudflare_set_worker_secret_from_env: return a copy of `err` with every exact
 * occurrence of the secret value replaced by a placeholder. The tool never puts the value into an error
 * itself, but cfRequest forwards Cloudflare's own errors[].message verbatim — and if that endpoint ever
 * echoed part of the submitted body in a validation error, the value would flow straight to the model
 * via fail(). Scrubbing here blocks that path regardless of what Cloudflare's API is confirmed to do.
 * String split/join (not a regex) so a value containing regex metacharacters is handled literally.
 */
function scrubSecret(err: unknown, secret: string): unknown {
  if (!secret) return err;
  const redacted = "[REDACTED]";
  if (err instanceof CloudflareApiError) {
    const scrubbedErrors = err.errors?.map((e) => ({ ...e, message: e.message.split(secret).join(redacted) }));
    return new CloudflareApiError(err.message.split(secret).join(redacted), err.status, scrubbedErrors);
  }
  if (err instanceof Error) {
    const next = new Error(err.message.split(secret).join(redacted));
    next.name = err.name;
    return next;
  }
  return err;
}

export function registerTools(server: McpServer): void {
  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_verify_token",
    {
      title: "Verify Cloudflare API Token",
      description: `Verify that the server's Cloudflare API token is valid and active.

Returns the token's ID and status ('active' if usable). Call this first if other tools are failing with auth errors. It does not reveal the token value itself.

Note: the /user/tokens/verify endpoint is user-scoped, so an account-scoped token can be rejected there (HTTP 401/403) even though it works fine for DNS. If that happens, this tool falls back to probing the Zones API and reports the token as valid when the probe succeeds.`,
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (): Promise<ToolResult> => {
      try {
        const { result } = await cfRequest<{ id: string; status: string; expires_on?: string }>(
          "GET",
          "/user/tokens/verify",
        );
        const structured = { id: result.id, status: result.status, ...(result.expires_on ? { expires_on: result.expires_on } : {}) };
        return ok(
          `Token is ${result.status} (id ${result.id}${result.expires_on ? `, expires ${result.expires_on}` : ""}). ` +
            "Next: cloudflare_list_zones to see which zones it can manage.",
          structured,
        );
      } catch (err) {
        // /user/tokens/verify is USER-scoped: an account-scoped token that is perfectly valid for
        // /zones and DNS can be rejected there with 401/403. On a 401/403, fall back to a Zones probe
        // before declaring the token invalid — a false negative on the first tool a user runs is
        // exactly the defect we're avoiding. Errors without a 401/403 status (network error, timeout,
        // or a non-JSON body that arrived without one) skip the probe and fail directly. A non-JSON
        // body that *does* carry 401/403 (e.g. an intercepting proxy) still probes harmlessly: the
        // probe hits the same failure and the original verify error is surfaced below.
        if (err instanceof CloudflareApiError && (err.status === 401 || err.status === 403)) {
          try {
            const { result_info } = await cfRequest<Zone[]>("GET", "/zones", { query: { per_page: 1 } });
            const total = result_info?.total_count;
            return ok(
              `This token could not use /user/tokens/verify (HTTP ${err.status}), which is normal for ` +
                "account-scoped tokens — but it IS valid: it can reach the Zones API" +
                (total !== undefined ? ` (${total} zone(s) visible)` : "") +
                ". Use cloudflare_list_zones to see what it can manage.",
              {
                usable: true,
                verified_via: "zones_probe",
                verify_status: err.status,
                ...(total !== undefined ? { zones_total: total } : {}),
              },
            );
          } catch {
            // The probe also failed: the token is genuinely invalid or too narrowly scoped to do
            // anything useful. Surface the ORIGINAL verify error (the real auth failure), not the
            // probe error.
            return fail(err);
          }
        }
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_list_zones",
    {
      title: "List Cloudflare Zones",
      description: `List the DNS zones (domains) this API token can access.

Args:
  - name (optional string): filter to an exact domain name.
  - page (optional int, default 1), per_page (optional int 1-50, default 50).

Returns per zone: id, name, status, paused. Use the zone 'name' or 'id' as the 'zone' argument to the DNS record tools.`,
      inputSchema: {
        name: z.string().optional().describe("Exact domain name filter, e.g. 'example.com'."),
        page: z.number().int().min(1).default(1).describe("Page number (default 1)."),
        per_page: z.number().int().min(1).max(50).default(50).describe("Zones per page, 1-50 (default 50)."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ name, page, per_page }): Promise<ToolResult> => {
      try {
        const { result, result_info } = await cfRequest<Zone[]>("GET", "/zones", {
          query: { name, page, per_page },
        });
        const zones = result.map((zn) => ({ id: zn.id, name: zn.name, status: zn.status, paused: zn.paused ?? false }));
        const total = result_info?.total_count ?? zones.length;
        const hasMore = result_info ? result_info.page * result_info.per_page < total : false;
        const lines = zones.map((zn) => `- ${zn.name} (${zn.status}${zn.paused ? ", paused" : ""}) [id: ${zn.id}]`);
        const text =
          zones.length === 0
            ? "No zones are visible to this API token. Check the token's zone scope in the Cloudflare dashboard."
            : `${total} zone(s) total, showing ${zones.length} (page ${page}):\n${lines.join("\n")}` +
              (hasMore ? `\nMore pages available — call again with page=${page + 1}.` : "");
        return ok(text, { total, count: zones.length, page, zones, has_more: hasMore });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_list_dns_records",
    {
      title: "List DNS Records",
      description: `List DNS records in a zone, with optional filters. ALWAYS use this to find a record's ID before updating or deleting it.

Args:
  - zone (string): domain name or zone ID.
  - type (optional): filter by record type (A, AAAA, CNAME, MX, TXT, ...).
  - name (optional string): exact record name filter, e.g. 'www.example.com'.
  - name_contains (optional string): substring match on record name.
  - content (optional string): exact content filter, e.g. an IP address.
  - page (optional int, default 1), per_page (optional int 1-100, default 50).

Returns per record: id, type, name, content, ttl (1 = Auto), proxied, priority, comment, modified_on.`,
      inputSchema: {
        zone: zoneParam,
        type: z.enum(RECORD_TYPES).optional().describe("Filter by DNS record type."),
        name: z.string().optional().describe("Exact record name (FQDN), e.g. 'www.example.com'."),
        name_contains: z.string().optional().describe("Substring to match within record names."),
        content: z.string().optional().describe("Exact record content, e.g. '203.0.113.10'."),
        page: z.number().int().min(1).default(1).describe("Page number (default 1)."),
        per_page: z.number().int().min(1).max(100).default(50).describe("Records per page, 1-100 (default 50)."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ zone, type, name, name_contains, content, page, per_page }): Promise<ToolResult> => {
      try {
        return await withZone(zone, async (zn) => {
          const { result, result_info } = await cfRequest<DnsRecord[]>("GET", `/zones/${zn.id}/dns_records`, {
            query: {
              type,
              name,
              "name.contains": name_contains,
              content,
              page,
              per_page,
            },
          });
          const records = result.map(slimRecord);
          const total = result_info?.total_count ?? records.length;
          const hasMore = result_info ? result_info.page * result_info.per_page < total : false;
          const header = `Zone ${zn.name} — ${total} matching record(s), showing ${records.length} (page ${page}):`;
          const text =
            records.length === 0
              ? `Zone ${zn.name} has no DNS records matching those filters.`
              : `${header}\n${records.map(formatRecordLine).join("\n")}` +
                (hasMore ? `\nMore pages available — call again with page=${page + 1}.` : "");
          return ok(text, { zone: { id: zn.id, name: zn.name }, total, count: records.length, page, records, has_more: hasMore });
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_get_dns_record",
    {
      title: "Get DNS Record",
      description: `Fetch a single DNS record by its ID, including full details.

Args:
  - zone (string): domain name or zone ID.
  - record_id (string): the record's ID.`,
      inputSchema: { zone: zoneParam, record_id: recordIdParam },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ zone, record_id }): Promise<ToolResult> => {
      try {
        return await withZone(zone, async (zn) => {
          const record = slimRecord(await getRecord(zn, record_id));
          return ok(`${formatRecordLine(record)}`, { zone: { id: zn.id, name: zn.name }, record });
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_create_dns_record",
    {
      title: "Create DNS Record",
      description: `Create a new DNS record in a zone.

Args:
  - zone (string): domain name or zone ID.
  - type (string): record type (A, AAAA, CNAME, MX, TXT, SRV, CAA, ...).
  - name (string): record name. Use '@' for the zone apex; relative names ('www') get the zone appended by Cloudflare.
  - content (string): record value — IP for A/AAAA, target hostname for CNAME/MX, text for TXT. Omit only when 'data' is used.
  - data (optional object): structured value for SRV/CAA/LOC/etc. records, per Cloudflare's API (e.g. SRV: {priority, weight, port, target}).
  - ttl (optional int): 1 = Auto (default), otherwise 30-86400 seconds.
  - proxied (optional bool, default false): route through Cloudflare's proxy. Only valid for A, AAAA, CNAME.
  - priority (optional int 0-65535): required for MX and URI records.
  - comment (optional string): note stored on the record.

Returns the created record including its new id.

Examples:
  - Point www at a server: type='A', name='www', content='203.0.113.10', proxied=true
  - Google verification: type='TXT', name='@', content='google-site-verification=...'
  - Mail: type='MX', name='@', content='mail.example.com', priority=10`,
      inputSchema: {
        zone: zoneParam,
        type: z.enum(RECORD_TYPES).describe("DNS record type."),
        name: z.string().min(1).max(255).describe("Record name; '@' for the zone apex."),
        content: z.string().max(2048).optional().describe("Record value. Required unless 'data' is provided."),
        data: z.record(z.unknown()).optional().describe("Structured value for SRV/CAA/LOC/etc. instead of 'content'."),
        ttl: ttlParam.default(1),
        proxied: z.boolean().default(false).describe("Proxy through Cloudflare (A/AAAA/CNAME only)."),
        priority: z.number().int().min(0).max(65_535).optional().describe("Required for MX and URI records."),
        comment: z
          .string()
          .max(500)
          .optional()
          .describe(
            "Optional note stored with the record. Cloudflare caps comments at 100 characters on Free-plan zones (500 on paid plans).",
          ),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ zone, type, name, content, data, ttl, proxied, priority, comment }): Promise<ToolResult> => {
      try {
        if (content === undefined && data === undefined) {
          throw new CloudflareApiError("Provide 'content' (or 'data' for structured types like SRV/CAA).");
        }
        if (proxied && !PROXYABLE_TYPES.has(type)) {
          throw new CloudflareApiError(`'proxied' is only valid for A, AAAA, and CNAME records (got type=${type}). Set proxied=false.`);
        }
        if (type === "MX" && priority === undefined) {
          throw new CloudflareApiError("MX records require 'priority' (e.g. 10).");
        }
        return await withZone(zone, async (zn) => {
          const { result } = await cfRequest<DnsRecord>("POST", `/zones/${zn.id}/dns_records`, {
            body: {
              type,
              name,
              ...(content !== undefined ? { content } : {}),
              ...(data !== undefined ? { data } : {}),
              ttl,
              ...(PROXYABLE_TYPES.has(type) ? { proxied } : {}),
              ...(priority !== undefined ? { priority } : {}),
              ...(comment !== undefined ? { comment } : {}),
            },
          });
          const record = slimRecord(result);
          return ok(`Created in ${zn.name}:\n${formatRecordLine(record)}`, {
            zone: { id: zn.id, name: zn.name },
            record,
          });
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_update_dns_record",
    {
      title: "Update DNS Record",
      description: `Update fields on an existing DNS record (partial update — only the fields you pass are changed).

Args:
  - zone (string): domain name or zone ID.
  - record_id (string): ID of the record to change (find it with cloudflare_list_dns_records).
  - type, name, content, data, ttl, proxied, priority, comment: any subset of fields to change.

Changing a record's type to MX requires 'priority'; 'proxied' is only valid when the resulting type is A, AAAA, or CNAME.

Returns both the record's state BEFORE and AFTER the change, so the edit can be reverted if needed. Changing live DNS can affect a running website or email — double-check the record ID and new values.`,
      inputSchema: {
        zone: zoneParam,
        record_id: recordIdParam,
        type: z.enum(RECORD_TYPES).optional().describe("New record type."),
        name: z.string().min(1).max(255).optional().describe("New record name."),
        content: z.string().max(2048).optional().describe("New record value."),
        data: z.record(z.unknown()).optional().describe("New structured value (SRV/CAA/LOC/etc.)."),
        ttl: ttlParam.optional(),
        proxied: z.boolean().optional().describe("Toggle Cloudflare proxying (A/AAAA/CNAME only)."),
        priority: z.number().int().min(0).max(65_535).optional().describe("New priority (MX/URI/SRV)."),
        comment: z
          .string()
          .max(500)
          .optional()
          .describe(
            "New comment. Pass an empty string to clear it. Cloudflare caps comments at 100 characters on Free-plan zones (500 on paid plans).",
          ),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ zone, record_id, type, name, content, data, ttl, proxied, priority, comment }): Promise<ToolResult> => {
      try {
        const patch: Record<string, unknown> = {};
        if (type !== undefined) patch.type = type;
        if (name !== undefined) patch.name = name;
        if (content !== undefined) patch.content = content;
        if (data !== undefined) patch.data = data;
        if (ttl !== undefined) patch.ttl = ttl;
        if (proxied !== undefined) patch.proxied = proxied;
        if (priority !== undefined) patch.priority = priority;
        if (comment !== undefined) patch.comment = comment;
        if (Object.keys(patch).length === 0) {
          throw new CloudflareApiError("No fields to update — pass at least one of type/name/content/data/ttl/proxied/priority/comment.");
        }
        return await withZone(zone, async (zn) => {
          const before = slimRecord(await getRecord(zn, record_id));
          const effectiveType = (patch.type as string | undefined) ?? before.type;
          if (patch.type === "MX" && patch.priority === undefined && before.priority === undefined) {
            throw new CloudflareApiError("MX records require 'priority' (e.g. 10).");
          }
          if (patch.proxied === true && !PROXYABLE_TYPES.has(effectiveType)) {
            throw new CloudflareApiError(`'proxied' is only valid for A, AAAA, and CNAME records (got type=${effectiveType}). Set proxied=false.`);
          }
          const { result } = await cfRequest<DnsRecord>("PATCH", `/zones/${zn.id}/dns_records/${record_id}`, {
            body: patch,
          });
          const after = slimRecord(result);
          return ok(
            `Updated record in ${zn.name}.\nBefore: ${formatRecordLine(before)}\nAfter:  ${formatRecordLine(after)}\n` +
              "(To revert, call cloudflare_update_dns_record again with the 'before' values.)",
            { zone: { id: zn.id, name: zn.name }, before, after },
          );
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_delete_dns_record",
    {
      title: "Delete DNS Record",
      description: `Permanently delete a DNS record. This cannot be undone by Cloudflare — the response includes a snapshot of the deleted record so it can be recreated with cloudflare_create_dns_record if needed.

Args:
  - zone (string): domain name or zone ID.
  - record_id (string): ID of the record to delete (verify it first with cloudflare_list_dns_records or cloudflare_get_dns_record).
  - confirm (boolean): must be true, as an explicit acknowledgement of a destructive action.

Deleting live DNS can take a website or email offline — verify the exact record before calling this.`,
      inputSchema: {
        zone: zoneParam,
        record_id: recordIdParam,
        confirm: z
          .boolean()
          .describe("Must be true. Confirms permanent deletion of the record."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ zone, record_id, confirm }): Promise<ToolResult> => {
      try {
        if (confirm !== true) {
          throw new CloudflareApiError("Deletion not confirmed. Re-call with confirm=true after verifying the record.");
        }
        return await withZone(zone, async (zn) => {
          const snapshot = slimRecord(await getRecord(zn, record_id));
          await cfRequest<{ id: string }>("DELETE", `/zones/${zn.id}/dns_records/${record_id}`);
          return ok(
            `Deleted from ${zn.name}:\n${formatRecordLine(snapshot)}\n` +
              "(To restore, recreate it with cloudflare_create_dns_record using the values above.)",
            { zone: { id: zn.id, name: zn.name }, deleted: snapshot },
          );
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_export_zone",
    {
      title: "Export Zone File (Backup)",
      description: `Export all DNS records in a zone as a standard BIND zone file. Useful as a backup before making bulk changes, or for migrating DNS.

Args:
  - zone (string): domain name or zone ID.

Returns the zone file as plain text (very large zones may be truncated; a truncated export is marked as incomplete and must not be used as a backup).`,
      inputSchema: { zone: zoneParam },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ zone }): Promise<ToolResult> => {
      try {
        return await withZone(zone, async (zn) => {
          const text = await cfRequestText("GET", `/zones/${zn.id}/dns_records/export`);
          return ok(
            `BIND zone file for ${zn.name}:\n\n${text}`,
            { zone: { id: zn.id, name: zn.name } },
            "this export was cut off and is an INCOMPLETE backup — do NOT restore from it. Export the full zone file from the Cloudflare dashboard (DNS → Records → Export) or the API directly.",
          );
        });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  // Registered unconditionally (even when disabled) so the mode can be read at CALL time, not
  // build time — this keeps behaviour test-friendly and lets an operator flip the env var without
  // restarting to change the registered tool set. Tradeoff: a DNS-only ('off') deployment still
  // advertises this tool in tools/list; it just refuses every call. An operator who wants the
  // capability to disappear entirely should run a separate, DNS-only server instance.
  server.registerTool(
    "cloudflare_api_request",
    {
      title: "Cloudflare API Request (guarded passthrough)",
      description: `Make a raw, authenticated request to ANY Cloudflare v4 API endpoint the server's token can reach — NOT just DNS. Use this only for Cloudflare operations the typed cloudflare_* DNS tools don't cover; prefer those tools whenever they fit (they validate inputs and return revertable before/after states).

This reaches the WHOLE Cloudflare API surface the token permits: reads like /user (account email), /accounts/{id}/members, audit logs, Workers, and Access/Zero Trust config; and, when writes are enabled, irreversible or account-wide actions such as DELETE /zones/{id} (deletes a zone and all its records/settings), API token creation/revocation, member/Access changes, and billing-affecting purchases. Treat it accordingly.

Args:
  - method (string): GET, HEAD, POST, PUT, PATCH, or DELETE. GET/HEAD are reads; POST/PUT/PATCH/DELETE are writes.
  - path (string): a v4 API path RELATIVE to https://api.cloudflare.com/client/v4, beginning with '/', e.g. '/zones' or '/zones/{zone_id}/purge_cache'. Absolute URLs, other hosts, and paths that escape the v4 base are refused.
  - query (optional object): query-string params, e.g. { per_page: 50, name: 'example.com' }.
  - body (optional object): JSON request body for write methods.
  - confirm (optional boolean): MUST be true for any write method.

Permission model (operator-controlled env var CLOUDFLARE_API_PASSTHROUGH, read fresh on each call):
  - unset / 'read' / anything unrecognized → GET/HEAD allowed; writes refused. This is the default (reads on).
  - 'full' → GET/HEAD allowed, and writes allowed only when confirm=true.
  - 'off' → the tool is disabled and every call is refused.

Safety: confirm=true is set by the model in its own tool call — it is NOT a verified human approval and provides no per-caller authorization. Once an operator sets 'full', any content that can steer this model (a fetched page, a DNS TXT record, an email) could induce a catastrophic call; confirm only guards against calling a write by accident. Non-JSON/binary responses (cert/PEM downloads, raw zone-file exports, Worker script source) are out of scope — use the typed tools or the dashboard for those.`,
      inputSchema: {
        method: z
          .enum(PASSTHROUGH_METHODS)
          .describe("HTTP method. GET/HEAD are reads; POST/PUT/PATCH/DELETE are writes (need CLOUDFLARE_API_PASSTHROUGH=full and confirm=true)."),
        path: z
          .string()
          .min(1)
          .describe(
            "Cloudflare v4 API path RELATIVE to https://api.cloudflare.com/client/v4, beginning with '/'. E.g. '/zones' or '/zones/{zone_id}/purge_cache'. Absolute URLs and other hosts are refused.",
          ),
        query: z
          .record(z.union([z.string(), z.number()]))
          .optional()
          .describe("Optional query-string parameters, e.g. { per_page: 50, name: 'example.com' }."),
        body: z.record(z.unknown()).optional().describe("Optional JSON request body for write methods (POST/PUT/PATCH)."),
        // Strict boolean ON PURPOSE — never z.coerce.boolean(), which treats the string "false" as
        // true (Boolean("false") === true) and would silently defeat this confirmation gate when an
        // MCP client or model sends confirm as a string.
        confirm: z
          .boolean()
          .optional()
          .describe("Must be true for mutating methods (POST/PUT/PATCH/DELETE). Acknowledges a write to the live Cloudflare account."),
      },
      // It CAN write (not read-only), writes may be destructive/irreversible, non-idempotent overall,
      // and it reaches an open, external world of endpoints.
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ method, path, query, body, confirm }): Promise<ToolResult> => {
      try {
        const mode = resolvePassthroughMode(process.env.CLOUDFLARE_API_PASSTHROUGH);
        if (mode === "off") {
          throw new CloudflareApiError(
            "The Cloudflare API passthrough is disabled (CLOUDFLARE_API_PASSTHROUGH=off). Set CLOUDFLARE_API_PASSTHROUGH=read " +
              "(GET/HEAD only) or =full (also POST/PUT/PATCH/DELETE, each requiring confirm=true) in the server's environment, " +
              "or unset it for the reads-on default. For DNS work, prefer the typed cloudflare_* tools.",
          );
        }

        // One normalized method value, used for BOTH the write-gate decision and dispatch — the zod
        // enum already fixes exact case, so no toUpperCase step exists that could let them diverge.
        const httpMethod: string = method;
        const mutating = MUTATING_METHODS.has(httpMethod);

        if (mutating) {
          if (mode !== "full") {
            throw new CloudflareApiError(
              `${httpMethod} is a mutating request, but CLOUDFLARE_API_PASSTHROUGH is 'read' — only GET/HEAD are allowed. ` +
                "Set CLOUDFLARE_API_PASSTHROUGH=full in the server's environment to permit writes, then retry with confirm=true.",
            );
          }
          if (confirm !== true) {
            throw new CloudflareApiError(
              `${httpMethod} ${path} would modify the live Cloudflare account, which is not confirmed. Re-call with ` +
                "confirm=true after verifying the method, path, and body. Writes can be irreversible (e.g. deleting a zone).",
            );
          }
        }

        // Host-pin the path BEFORE any network call. (doFetch re-validates as the single URL
        // construction site, but gating here keeps the refusal explicit and network-free.)
        validateApiPath(path);

        const res = await cfApiPassthrough(httpMethod, path, { query, body });
        const header = `${httpMethod} ${path} → HTTP ${res.status}`;
        if (res.json !== undefined) {
          return ok(
            `${header}\n${JSON.stringify(res.json, null, 2)}`,
            { status: res.status, ok: res.ok, response: res.json },
            "narrow the endpoint or add query filters/pagination to reduce the response size",
          );
        }
        if (res.nonJson) {
          return ok(
            `${header} (non-JSON body)\n${res.text ?? ""}`,
            { status: res.status, ok: res.ok, body: res.text ?? "" },
            "the non-JSON response body was truncated",
          );
        }
        return ok(`${header} (${res.ok ? "success" : "failure"}, no response body)`, { status: res.status, ok: res.ok });
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  // Tool #10: set a Worker secret whose VALUE is read from the SERVER's own environment. The model
  // only names WHICH allowlisted env var to read — the value never appears in the tool call, output,
  // structuredContent, or any log. Registered unconditionally so the two allowlists are read at CALL
  // time (like the passthrough mode); with either allowlist empty every call is refused.
  server.registerTool(
    "cloudflare_set_worker_secret_from_env",
    {
      title: "Set Worker Secret from Server Env",
      description: `Set a Cloudflare Worker secret whose VALUE is read from THIS SERVER's own environment — the secret value never passes through the model, this tool call, the response, or any log. The model only names WHICH allowlisted server env var to read and which Worker/binding to set.

Args:
  - script_name (string): the Worker script to set the secret on. Must be in CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST.
  - secret_name (string): the secret's binding name inside the Worker (accessed as env.<secret_name>).
  - env_var (string): the name of the server env var whose value becomes the secret. Must be in CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST and not on the hard denylist.
  - account_id (optional string): 32-char account ID; defaults to CLOUDFLARE_ACCOUNT_ID or the token's sole account.
  - confirm (boolean): must be true — acknowledges a write to the live account.

Two operator opt-ins gate this (both empty by default ⇒ disabled):
  - CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST: comma-separated env var NAMES the tool may read (e.g. "STICKER_IT_KEY").
  - CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST: comma-separated Worker script NAMES that may receive a secret.
The env-var names CLOUDFLARE_API_TOKEN, MCP_AUTH_TOKEN, and ALLOW_UNAUTHENTICATED can NEVER be exposed, even if allowlisted.

Safety: confirm=true is set by the model in its own tool call — it is NOT a verified human approval. The allowlists are the real gate: a value can only be read from an operator-approved env var and can only land on an operator-approved script.`,
      inputSchema: {
        script_name: scriptNameParam,
        secret_name: z
          .string()
          .regex(WORKER_SECRET_NAME_RE, "secret_name must be a valid binding identifier (letter/underscore first, then letters/digits/underscore).")
          .describe("The secret's binding name inside the Worker (accessed as env.<secret_name>)."),
        env_var: z
          .string()
          .regex(ENV_VAR_NAME_RE, "env_var must be a valid environment variable name.")
          .describe("Name of the server env var whose value becomes the secret. Must be in CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST."),
        account_id: accountIdParam.optional(),
        // Strict boolean ON PURPOSE (never z.coerce.boolean(), which treats the string "false" as true).
        confirm: z.boolean().describe("Must be true. Confirms writing the secret to the live Cloudflare account."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ script_name, secret_name, env_var, account_id, confirm }): Promise<ToolResult> => {
      try {
        const allowlistRaw = process.env.CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST;
        const scriptAllowlistRaw = process.env.CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST;

        // 1. Feature disabled unless the operator opted in with an env-var allowlist. This refusal
        //    reveals nothing about any configured name.
        if (parseEnvAllowlist(allowlistRaw).length === 0) {
          throw new CloudflareApiError(
            "Setting Worker secrets from the server environment is disabled. Set " +
              "CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST to the env var name(s) permitted (e.g. STICKER_IT_KEY).",
          );
        }
        // 1b. Paired opt-in: a secret can only land on an operator-approved script. Empty ⇒ no script
        //     is approved, so a model-deployed Worker can never receive an allowlisted secret.
        if (parseScriptAllowlist(scriptAllowlistRaw).length === 0) {
          throw new CloudflareApiError(
            "Setting Worker secrets is disabled because no target script is approved. Set " +
              "CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST to the Worker script name(s) permitted to receive secrets.",
          );
        }

        // 2. Confirm-first (matches cloudflare_delete_dns_record): an unconfirmed write is refused
        //    BEFORE any name-specific check, so it can't be used to probe which env vars exist.
        if (confirm !== true) {
          throw new CloudflareApiError(
            "Not confirmed. Re-call with confirm=true to set the Worker secret. Note: confirm is set by the " +
              "model in its own tool call — it is NOT a verified human approval; the allowlists are the real gate.",
          );
        }

        // 3. env_var must be allowlisted and not denylisted. This message names ONLY env_var — never
        //    any other configured env var name or value.
        const access = resolveEnvVarAccess(env_var, allowlistRaw);
        if (!access.ok) {
          if (access.reason === "denylisted") {
            throw new CloudflareApiError(`'${env_var}' can never be exposed as a Worker secret.`);
          }
          throw new CloudflareApiError(`env var '${env_var}' is not in CLOUDFLARE_WORKER_SECRET_ENV_ALLOWLIST.`);
        }

        // 4. script_name must be an operator-approved target.
        if (!isScriptAllowedForSecret(script_name, scriptAllowlistRaw)) {
          throw new CloudflareApiError(
            `Worker script '${script_name}' is not in CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST — a secret can ` +
              "only be set on a script the operator explicitly approved.",
          );
        }

        // 5. Read the value from the server env. It is never printed on any path.
        const value = process.env[env_var];
        if (value === undefined || value === "") {
          throw new CloudflareApiError(`allowlisted env var '${env_var}' is not set in the server environment.`);
        }

        // 6. Resolve the account and PUT the secret. The request body carries the value; scrub the
        //    value out of any error before it can reach the model via fail().
        const accountId = await resolveAccountId(account_id);
        try {
          await cfRequest<{ name: string; type: string }>("PUT", `/accounts/${accountId}/workers/scripts/${script_name}/secrets`, {
            body: { name: secret_name, text: value, type: "secret_text" },
          });
        } catch (err) {
          throw scrubSecret(err, value);
        }

        // 7. Success — the value is NEVER included. structuredContent is a HARDCODED field list (never
        //    a spread of the Cloudflare response), so no response field can smuggle extra data through.
        return ok(
          `Set secret '${secret_name}' on Worker '${script_name}' from server env var '${env_var}' (value not shown).`,
          { account_id: accountId, script_name, secret_name, source_env_var: env_var },
        );
      } catch (err) {
        return fail(err);
      }
    },
  );

  // ------------------------------------------------------------------
  // Tool #11: upload/deploy a Worker script via multipart/form-data. Gated by an explicit operator
  // opt-in (CLOUDFLARE_WORKERS_DEPLOY_ENABLE=true) PLUS confirm=true — this can run arbitrary
  // attacker-authored JavaScript with network egress inside the account, so it is off by default.
  server.registerTool(
    "cloudflare_deploy_worker",
    {
      title: "Deploy Cloudflare Worker",
      description: `Upload and deploy a Cloudflare Worker script (multipart upload). This runs the given JavaScript inside the Cloudflare account, so it is disabled unless the operator opts in.

Separation of duties: a script listed in CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST (i.e. one that may RECEIVE an env-sourced secret via cloudflare_set_worker_secret_from_env) is REFUSED by this tool — the same code can never be both model-authored here AND handed an allowlisted secret. Deploy secret-bearing Workers out-of-band (Cloudflare dashboard or wrangler), then set their secrets with cloudflare_set_worker_secret_from_env. Do NOT embed secrets (API keys, tokens) in the deployed code — anyone who can read the Worker can read them.

Args:
  - script_name (string): the Worker script name.
  - script (string): the Worker source code. (Passing code through the model is fine — it is not a secret.)
  - main_module (string, default "worker.js"): entrypoint module filename (esm) / script part name.
  - module_type ("esm" | "service_worker", default "esm"): module format.
  - compatibility_date (optional string, e.g. "2024-11-01").
  - compatibility_flags (optional string[]).
  - bindings (optional array of objects): passed through into metadata.bindings (e.g. KV, secret_text, plain_text).
  - account_id (optional string): 32-char account ID; defaults to CLOUDFLARE_ACCOUNT_ID or the token's sole account.
  - confirm (boolean): must be true — acknowledges deploying live code.

Operator opt-in: CLOUDFLARE_WORKERS_DEPLOY_ENABLE=true must be set (default: disabled). Safety: confirm=true is set by the model in its own tool call — it is NOT a verified human approval; the env-var opt-in is the real gate. Treat enabling it as granting the ability to run arbitrary code within the token's Cloudflare scope, so keep the token narrow.`,
      inputSchema: {
        script_name: scriptNameParam,
        script: z.string().min(1).max(5_000_000).describe("The Worker source code."),
        main_module: z
          .string()
          .regex(MODULE_NAME_RE, "main_module must be a valid module filename (letters, digits, '.', '_', '-').")
          .default("worker.js")
          .describe("Entrypoint module filename (esm) / script part name. Default 'worker.js'."),
        module_type: z.enum(["esm", "service_worker"]).default("esm").describe("Module format. Default 'esm'."),
        compatibility_date: z
          .string()
          .regex(/^\d{4}-\d{2}-\d{2}$/, "compatibility_date must be YYYY-MM-DD.")
          .optional()
          .describe("Runtime compatibility date, e.g. '2024-11-01'."),
        compatibility_flags: z.array(z.string()).optional().describe("Runtime compatibility flags."),
        bindings: z
          .array(z.record(z.unknown()))
          .optional()
          .describe("Binding objects passed through into metadata.bindings (e.g. { type:'kv_namespace', name:'KV', namespace_id:'...' })."),
        account_id: accountIdParam.optional(),
        // Strict boolean ON PURPOSE (never z.coerce.boolean()).
        confirm: z.boolean().describe("Must be true. Confirms deploying live code to the Cloudflare account."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ script_name, script, main_module, module_type, compatibility_date, compatibility_flags, bindings, account_id, confirm }): Promise<ToolResult> => {
      try {
        // 1. Operator opt-in (two-factor with confirm, mirroring the passthrough's 'full' mode).
        if (!isWorkersDeployEnabled(process.env.CLOUDFLARE_WORKERS_DEPLOY_ENABLE)) {
          throw new CloudflareApiError(
            "Deploying Workers is disabled. Set CLOUDFLARE_WORKERS_DEPLOY_ENABLE=true in the server's environment " +
              "to allow it (each deploy still requires confirm=true). This tool can run arbitrary JavaScript with " +
              "network egress inside the Cloudflare account, so keep the token narrowly scoped.",
          );
        }
        // 2. Confirm-first.
        if (confirm !== true) {
          throw new CloudflareApiError(
            "Not confirmed. Re-call with confirm=true to deploy the Worker. Note: confirm is set by the model in " +
              "its own tool call — it is NOT a verified human approval; CLOUDFLARE_WORKERS_DEPLOY_ENABLE is the real gate.",
          );
        }

        // 3. Separation of duties (hard structural gate — runs regardless of confirm): a script that
        //    may RECEIVE an env-sourced secret must NOT be deployable by this tool. Otherwise the model
        //    could deploy attacker-authored code to an allowlisted script name and then bind the
        //    allowlisted secret to it, letting the Worker's own network egress exfiltrate the value.
        //    Refusing here means a secret only ever lands on code the operator deployed out-of-band.
        if (isScriptAllowedForSecret(script_name, process.env.CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST)) {
          throw new CloudflareApiError(
            `Worker '${script_name}' is reserved for receiving an env-sourced secret (it is listed in ` +
              "CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST) and cannot be deployed by this tool. To keep the secret " +
              "away from model-authored code, deploy secret-bearing Workers out-of-band (Cloudflare dashboard or " +
              "wrangler); this tool deploys only Workers that never receive an allowlisted secret.",
          );
        }

        // Build the multipart layout from the PURE builder, then assemble the FormData from it. The
        // Content-Type (with boundary) is set by undici — never manually — inside cfRequestForm/doFetch.
        const plan = buildWorkerUploadPlan({
          mainModule: main_module,
          moduleType: module_type,
          compatibilityDate: compatibility_date,
          compatibilityFlags: compatibility_flags,
          bindings,
        });
        const form = new FormData();
        for (const part of plan.parts) {
          const value = part.role === "metadata" ? JSON.stringify(plan.metadata) : script;
          const blob = new Blob([value], { type: part.contentType });
          if (part.filename !== undefined) form.append(part.field, blob, part.filename);
          else form.append(part.field, blob);
        }

        const accountId = await resolveAccountId(account_id);
        const { result } = await cfRequestForm<{ id?: string; etag?: string; created_on?: string; modified_on?: string; startup_time_ms?: number }>(
          "PUT",
          `/accounts/${accountId}/workers/scripts/${script_name}`,
          form,
        );
        const summary: Record<string, unknown> = {
          account_id: accountId,
          script_name,
          module_type,
          main_module,
          ...(result?.id ? { id: result.id } : {}),
          ...(result?.etag ? { etag: result.etag } : {}),
          ...(result?.created_on ? { created_on: result.created_on } : {}),
          ...(result?.modified_on ? { modified_on: result.modified_on } : {}),
          ...(result?.startup_time_ms !== undefined ? { startup_time_ms: result.startup_time_ms } : {}),
        };
        return ok(
          `Deployed Worker '${script_name}' (${module_type}, entry ${main_module}) to account ${accountId}.` +
            (result?.id ? ` id=${result.id}` : "") +
            (result?.etag ? ` etag=${result.etag}` : "") +
            "\nReminder: do not embed secrets in the code. This Worker is NOT in CLOUDFLARE_WORKER_SECRET_SCRIPT_ALLOWLIST " +
            "(that is why it was deployable here), so it cannot receive an env-sourced secret via " +
            "cloudflare_set_worker_secret_from_env; a Worker that needs an allowlisted secret must be deployed out-of-band.",
          summary,
        );
      } catch (err) {
        return fail(err);
      }
    },
  );
}

export const TOOL_COUNT = 11;
