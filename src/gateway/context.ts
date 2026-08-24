/**
 * Per-request tenant context for gateway mode.
 *
 * In gateway (multi-tenant) mode the server handles many agents in one process. Each inbound MCP
 * request is authenticated to ONE agent, resolved to ONE Cloudflare API token. That token — and the
 * agent name it belongs to — must ride along with everything the request does, WITHOUT being passed
 * explicitly through every function (cloudflare.ts, the tools, zone resolution, …). AsyncLocalStorage
 * is exactly that: an ambient, request-scoped value that cannot bleed between concurrently-served
 * requests the way a module-level variable would.
 *
 * Nothing here reads or falls back to process.env.CLOUDFLARE_API_TOKEN — that fail-open fallback is
 * decided in cloudflare.ts (single-tenant only), never here.
 */
import { AsyncLocalStorage } from "node:async_hooks";

/** The ambient, per-request identity: which agent, and which Cloudflare token to act as. */
export interface RequestContext {
  /** The resolved Cloudflare API token this request must use. Never logged, never returned. */
  cloudflareToken: string;
  /** Human-readable agent name, for audit/log lines (safe to log — it is not a secret). */
  agentName: string;
}

/** The single AsyncLocalStorage instance carrying the active RequestContext. */
export const requestContext = new AsyncLocalStorage<RequestContext>();

/** The Cloudflare token bound to the current request, or undefined when no context is active. */
export function getRequestToken(): string | undefined {
  return requestContext.getStore()?.cloudflareToken;
}

/** The agent name bound to the current request, or undefined when no context is active. */
export function getRequestAgentName(): string | undefined {
  return requestContext.getStore()?.agentName;
}

/** Run `fn` with `ctx` established as the active RequestContext for the duration of the call. */
export function runWithToken<T>(ctx: RequestContext, fn: () => T): T {
  return requestContext.run(ctx, fn);
}

/**
 * True when the server is running in multi-tenant gateway mode (GATEWAY_ENABLE=true).
 *
 * Strict, fail-closed comparison to the exact string "true": any other value (unset, "1", "TRUE",
 * " true") keeps the server in single-tenant mode, so gateway mode can never be turned on by accident.
 */
export function gatewayEnabled(): boolean {
  return process.env.GATEWAY_ENABLE === "true";
}
