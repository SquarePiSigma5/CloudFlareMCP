import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  CloudflareApiError,
  DnsRecord,
  SlimRecord,
  Zone,
  cfRequest,
  cfRequestText,
  formatRecordLine,
  resolveZone,
  slimRecord,
  truncate,
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

export function registerTools(server: McpServer): void {
  // ------------------------------------------------------------------
  server.registerTool(
    "cloudflare_verify_token",
    {
      title: "Verify Cloudflare API Token",
      description: `Verify that the server's Cloudflare API token is valid and active.

Returns the token's ID and status ('active' if usable). Call this first if other tools are failing with auth errors. It does not reveal the token value itself.`,
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
        const zn = await resolveZone(zone);
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
        const zn = await resolveZone(zone);
        const record = slimRecord(await getRecord(zn, record_id));
        return ok(`${formatRecordLine(record)}`, { zone: { id: zn.id, name: zn.name }, record });
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
        const zn = await resolveZone(zone);
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
        const zn = await resolveZone(zone);
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
        const zn = await resolveZone(zone);
        const snapshot = slimRecord(await getRecord(zn, record_id));
        await cfRequest<{ id: string }>("DELETE", `/zones/${zn.id}/dns_records/${record_id}`);
        return ok(
          `Deleted from ${zn.name}:\n${formatRecordLine(snapshot)}\n` +
            "(To restore, recreate it with cloudflare_create_dns_record using the values above.)",
          { zone: { id: zn.id, name: zn.name }, deleted: snapshot },
        );
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
        const zn = await resolveZone(zone);
        const text = await cfRequestText("GET", `/zones/${zn.id}/dns_records/export`);
        return ok(
          `BIND zone file for ${zn.name}:\n\n${text}`,
          { zone: { id: zn.id, name: zn.name } },
          "this export was cut off and is an INCOMPLETE backup — do NOT restore from it. Export the full zone file from the Cloudflare dashboard (DNS → Records → Export) or the API directly.",
        );
      } catch (err) {
        return fail(err);
      }
    },
  );
}

export const TOOL_COUNT = 8;
