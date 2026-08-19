# cloudflare-dns-mcp-server

A Model Context Protocol (MCP) server that lets any MCP-compatible LLM client (Claude Code, Claude Desktop, claude.ai custom connectors, Cursor, and others) read and edit DNS records on your Cloudflare account. It runs as a streamable HTTP server (stateless JSON mode, the current MCP standard for remote servers), with an stdio mode for clients that launch local subprocess servers.

## Tools

| Tool | What it does |
| --- | --- |
| `cloudflare_verify_token` | Confirm the API token is valid and active |
| `cloudflare_list_zones` | List domains the token can manage |
| `cloudflare_list_dns_records` | List/filter records in a zone (source of record IDs) |
| `cloudflare_get_dns_record` | Fetch one record by ID |
| `cloudflare_create_dns_record` | Create A/AAAA/CNAME/MX/TXT/SRV/CAA/etc. records |
| `cloudflare_update_dns_record` | Partial update; returns before/after so edits can be reverted |
| `cloudflare_delete_dns_record` | Delete (requires `confirm=true`); returns a snapshot for recreation |
| `cloudflare_export_zone` | Export the zone as a BIND file — take a backup before bulk changes |

## Setup

Requires Node.js 20+.

**1. Create a scoped Cloudflare API token.** In the Cloudflare dashboard go to My Profile → API Tokens → Create Token → use the **Edit zone DNS** template, and under Zone Resources limit it to the specific zone(s) you want the model to manage. Do not use the Global API Key — a scoped token means the worst-case blast radius is DNS on those zones only.

**2. Install and build:**

```bash
npm install
npm run build
```

**3. Configure and run:**

```bash
cp .env.example .env   # fill in tokens, then either export them or use a loader
export CLOUDFLARE_API_TOKEN="cf_..."
export MCP_AUTH_TOKEN="$(openssl rand -hex 24)"   # protects the MCP endpoint itself
npm start
```

The MCP endpoint is now at `http://127.0.0.1:8787/mcp` (health check at `/healthz`). Environment knobs: `HOST` (default `127.0.0.1`), `PORT` (default `8787`), `TRANSPORT` (`http` default, or `stdio`), `ALLOWED_ORIGINS` (extra browser origins, comma-separated).

**4. Smoke-test it:**

```bash
MCP_AUTH_TOKEN="<same token>" npm run smoke
```

This connects with a real MCP client, lists the 8 tools, and calls `cloudflare_verify_token`. You can also point MCP Inspector at the URL: `npx @modelcontextprotocol/inspector`.

## Connecting clients

**Claude Code:**

```bash
claude mcp add --transport http cloudflare-dns http://127.0.0.1:8787/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

**Cursor / other clients with JSON config** — any client that supports streamable HTTP with custom headers works the same way:

```json
{
  "mcpServers": {
    "cloudflare-dns": {
      "url": "http://127.0.0.1:8787/mcp",
      "headers": { "Authorization": "Bearer <MCP_AUTH_TOKEN>" }
    }
  }
}
```

**Clients that only launch local stdio servers:**

```json
{
  "mcpServers": {
    "cloudflare-dns": {
      "command": "node",
      "args": ["/path/to/cloudflare-dns-mcp-server/dist/index.js"],
      "env": { "CLOUDFLARE_API_TOKEN": "cf_...", "TRANSPORT": "stdio" }
    }
  }
}
```

**claude.ai / Claude mobile custom connectors** need a public HTTPS URL — they can't reach `localhost`. The quickest path is a Cloudflare Tunnel from the machine running the server:

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

Important caveat: the claude.ai custom-connector UI authenticates via OAuth or not at all — it has no field for a static bearer header. That leaves two options for remote use: put the tunnel behind Cloudflare Access (service auth) and terminate auth there, or run with `MCP_AUTH_TOKEN` unset and rely on the tunnel URL staying secret — which is meaningfully weaker protection for something that can edit your DNS. With a Cloudflare Tunnel the server still binds `127.0.0.1`, so no opt-in is needed; but if you expose the port directly instead of tunnelling, an unauthenticated non-localhost bind requires `ALLOW_UNAUTHENTICATED=true`. Check the current claude.ai connector auth options before choosing; this changes over time.

## Security notes

The server binds to `127.0.0.1` by default and refuses to start without `CLOUDFLARE_API_TOKEN`. If you bind to any other address without `MCP_AUTH_TOKEN` set, it refuses to start — anyone who can reach the port can edit your DNS — unless you set `ALLOW_UNAUTHENTICATED=true`, which is only appropriate when auth is terminated upstream (e.g. Cloudflare Access). Browser-origin requests are rejected unless from localhost or `ALLOWED_ORIGINS` (DNS-rebinding protection). Tokens are read from the environment, never logged, and never returned by any tool.

On the model-safety side: deletion requires an explicit `confirm=true` argument, updates return before/after states so any change can be reverted, and `cloudflare_export_zone` gives a one-call BIND backup — worth asking your model to run before bulk edits. DNS edits propagate to the real internet; a wrong record can take a site or mail offline, so review what the model proposes before letting it loose on production zones.

## Development

```bash
npm run build    # compile TypeScript → dist/
npm start        # run HTTP server
npm run smoke    # end-to-end client test against the running server
```

Source layout: `src/index.ts` (transports, auth middleware), `src/cloudflare.ts` (API client, zone resolution, formatting), `src/tools.ts` (tool registrations).

## License

[MIT](LICENSE)
