# cloudflare-dns-mcp-server

A Model Context Protocol (MCP) server for the **Cloudflare API**. It gives any MCP-compatible LLM client (Claude Code, Claude Desktop, claude.ai custom connectors, ChatGPT connectors, Cursor, and others) eight typed convenience tools for common DNS operations, **plus** `cloudflare_api_request` — a guarded passthrough that can reach any Cloudflare v4 API endpoint the token is scoped for. What the server can actually do is set entirely by the API token's scope: a DNS-scoped token keeps it to DNS, while a broader token unlocks more of the v4 surface (reads by default, writes behind an explicit opt-in). It does not add anything outside Cloudflare's own API.

Connect over **stdio** (for clients that launch a local subprocess) or over **streamable HTTP** in stateless JSON mode (the current MCP standard for remote servers). See [Connecting MCP clients](#connecting-mcp-clients).

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
| `cloudflare_api_request` | Guarded raw passthrough to any Cloudflare v4 endpoint the token can reach (reads on by default — see [Beyond DNS](#beyond-dns-raw-api-passthrough)) |

## Setup

Requires Node.js 20+.

**1. Create a scoped Cloudflare API token.** The token is the real security boundary — what the server can do is exactly what the token is scoped for. For DNS work, in the Cloudflare dashboard go to My Profile → API Tokens → Create Token → use the **Edit zone DNS** template, and under Zone Resources limit it to the specific zone(s) you want the model to manage. Do not use the Global API Key. Grant only the permissions the task needs: a DNS-scoped token means the worst-case blast radius is DNS on those zones, even though `cloudflare_api_request` can reach any endpoint the token permits (see [Beyond DNS](#beyond-dns-raw-api-passthrough)).

**2. Install and build:**

```bash
npm install
npm run build
```

**3. Configure and run:**

```bash
cp .env.example .env   # fill in tokens, then either export them or use a loader
export CLOUDFLARE_API_TOKEN="cfat_..."
export MCP_AUTH_TOKEN="$(openssl rand -hex 24)"   # protects the MCP endpoint itself
npm start
```

The MCP endpoint is now at `http://127.0.0.1:8787/mcp` (health check at `/healthz`). Environment knobs: `HOST` (default `127.0.0.1`), `PORT` (default `8787`), `TRANSPORT` (`http` default, or `stdio`), `ALLOWED_ORIGINS` (extra browser origins, comma-separated).

**4. Smoke-test it:**

```bash
MCP_AUTH_TOKEN="<same token>" npm run smoke
```

This connects with a real MCP client, lists the 9 tools, and calls `cloudflare_verify_token`. You can also point MCP Inspector at the URL: `npx @modelcontextprotocol/inspector`.

## Connecting MCP clients

The server speaks the two standard MCP transports; pick by how your client connects. A client that **launches a local subprocess** uses stdio. A client that **connects to a URL** uses HTTP. The same nine tools are exposed either way.

### Local (stdio)

For clients that launch a local subprocess server — Claude Desktop, Cursor, Cline, and similar. The client runs `dist/index.js` with `TRANSPORT=stdio` and passes the Cloudflare token in its own `env` block. There is no network surface, so **no `MCP_AUTH_TOKEN` is needed**.

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "node",
      "args": ["/absolute/path/to/cloudflare-dns-mcp-server/dist/index.js"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "cfat_...",
        "TRANSPORT": "stdio",
        "CLOUDFLARE_API_PASSTHROUGH": "read"
      }
    }
  }
}
```

The token can live in this `env` block or in the shell that launches the client. After `npm install -g .`, the `cloudflare-dns-mcp-server` bin is on your `PATH`, so you can set `"command": "cloudflare-dns-mcp-server"` (dropping `args`) instead of `node` plus the absolute path.

### Remote (HTTP)

For clients that connect to a URL — ChatGPT custom connectors / MCP, Claude Code, claude.ai custom connectors, and any streamable-HTTP client.

1. **Run the server** (`npm start`, or [Docker](#running-with-docker)) and set `MCP_AUTH_TOKEN` so the `/mcp` endpoint requires a bearer token.
2. **Put it behind HTTPS** — a reverse proxy, your platform's TLS, or a Cloudflare Tunnel (`cloudflared tunnel --url http://127.0.0.1:8787`). Remote clients can't reach `localhost`.
3. **Add it in the client** as a custom MCP server / connector pointing at `https://<host>/mcp` with header `Authorization: Bearer <MCP_AUTH_TOKEN>`.

Claude Code:

```bash
claude mcp add --transport http cloudflare https://<host>/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

Generic JSON config (any streamable-HTTP client that supports custom headers):

```json
{
  "mcpServers": {
    "cloudflare": {
      "url": "https://<host>/mcp",
      "headers": { "Authorization": "Bearer <MCP_AUTH_TOKEN>" }
    }
  }
}
```

**ChatGPT** connects to remote MCP servers by URL — add it under its connectors / MCP settings (typically requires developer mode). It needs a public HTTPS URL. As with the claude.ai connector UI, exact auth-field support (a static bearer header vs OAuth) varies by client version, so check the client's current MCP docs. If the client can't send a static `Authorization` header, terminate auth upstream instead (e.g. Cloudflare Access) — as described in the next paragraph.

**claude.ai / Claude mobile custom connectors** need a public HTTPS URL — they can't reach `localhost`. The quickest path is a Cloudflare Tunnel from the machine running the server:

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

Important caveat: the claude.ai custom-connector UI authenticates via OAuth or not at all — it has no field for a static bearer header. That leaves two options for remote use: put the tunnel behind Cloudflare Access (service auth) and terminate auth there, or run with `MCP_AUTH_TOKEN` unset and rely on the tunnel URL staying secret — which is meaningfully weaker protection for something that can change your Cloudflare account. With a Cloudflare Tunnel the server still binds `127.0.0.1`, so no opt-in is needed; but if you expose the port directly instead of tunnelling, an unauthenticated non-localhost bind requires `ALLOW_UNAUTHENTICATED=true`. Check the current connector auth options before choosing; this changes over time.

## Running with Docker

The image is self-contained and stateless, and **no secret is ever built into it** — tokens are passed at run time. Because a container must bind `0.0.0.0` to be reachable through a published port, `MCP_AUTH_TOKEN` is **required**: the server fails closed without it (unless `ALLOW_UNAUTHENTICATED=true`, for when auth is terminated upstream). This is the correct behavior for a network-exposed server.

```bash
docker build -t cloudflare-mcp .

docker run --rm -p 8787:8787 \
  -e CLOUDFLARE_API_TOKEN=cfat_... \
  -e MCP_AUTH_TOKEN="$(openssl rand -hex 24)" \
  cloudflare-mcp
# add -e CLOUDFLARE_API_PASSTHROUGH=full to also allow passthrough writes (see Beyond DNS)
```

Or with Compose, which reads secrets from a gitignored `.env` you create (copy `.env.example`) or from your shell — never from the compose file:

```bash
docker compose up --build
```

Either way the endpoint is at `http://<host>:8787/mcp` (health check at `/healthz`). Put HTTPS in front of the published port and add it to a client per [Remote (HTTP)](#remote-http) above.

## Security notes

The server binds to `127.0.0.1` by default and refuses to start without `CLOUDFLARE_API_TOKEN`. If you bind to any other address without `MCP_AUTH_TOKEN` set, it refuses to start — anyone who can reach the port can edit your DNS — unless you set `ALLOW_UNAUTHENTICATED=true`, which is only appropriate when auth is terminated upstream (e.g. Cloudflare Access). Browser-origin requests are rejected unless from localhost or `ALLOWED_ORIGINS` (DNS-rebinding protection). Tokens are read from the environment, never logged, and never returned by any tool.

On the model-safety side: deletion requires an explicit `confirm=true` argument, updates return before/after states so any change can be reverted, and `cloudflare_export_zone` gives a one-call BIND backup — worth asking your model to run before bulk edits. DNS edits propagate to the real internet; a wrong record can take a site or mail offline, so review what the model proposes before letting it loose on production zones.

The ninth tool, `cloudflare_api_request`, reaches past DNS: by default (`read` mode) it lets the model `GET` any endpoint the configured token can reach — not just DNS — while writes require `CLOUDFLARE_API_PASSTHROUGH=full` plus `confirm=true` (see [Beyond DNS](#beyond-dns-raw-api-passthrough)). The Cloudflare token's own scope is the real boundary here, so keep it narrow — or set `CLOUDFLARE_API_PASSTHROUGH=off` for a strictly DNS-only server.

## Beyond DNS: raw API passthrough

The eight typed tools above only touch DNS. `cloudflare_api_request` is a guarded passthrough that can call **any** Cloudflare v4 API endpoint the configured token is scoped for — zones, cache, Workers, R2, members, tokens, and so on. It exists so one server can use whatever permissions the token holds — reads are available by default, and writes sit behind an explicit opt-in plus per-call confirmation.

It is controlled entirely by one environment variable, `CLOUDFLARE_API_PASSTHROUGH`, read fresh on every call:

| Value | Behaviour |
| --- | --- |
| _unset_ / `read` / anything unrecognized | **`read` — the default.** `GET`/`HEAD` allowed; mutating methods (`POST`/`PUT`/`PATCH`/`DELETE`) refused. Only an exact `full` or `off` changes this, so a typo can never enable writes. |
| `full` | Reads allowed, and mutating methods allowed **only when the call includes `confirm=true`**. |
| `off` | **Disabled.** Every call is refused. Use this for a strictly DNS-only server. |

The tool is compiled in unconditionally and always appears in `tools/list`. By default it serves reads; set `CLOUDFLARE_API_PASSTHROUGH=full` to allow writes, or `=off` to disable it entirely. If you want a strictly DNS-only server, set `=off` and rely on the typed tools above.

Read this first — and especially before setting `full`:

- **The default `read` is scoped by the token, not by DNS.** The model can `GET` anything the token can reach — `/user` (your account email), `/accounts/{id}/members`, audit logs, Workers script metadata, Access/Zero Trust config, API-token metadata, and more. If you want a strictly DNS-only server, set `CLOUDFLARE_API_PASSTHROUGH=off`. The token's own scope is the real boundary — keep it as narrow as the work allows.
- **`full` grants whole-account power to every holder of `MCP_AUTH_TOKEN`.** Authorization on this server is a single shared bearer token for the whole `/mcp` endpoint, with no per-caller identity or per-tool scoping (and it may sit behind an upstream proxy, or run with `ALLOW_UNAUTHENTICATED=true`). `CLOUDFLARE_API_PASSTHROUGH` is one process-wide switch, and the per-request `confirm` flag narrows nothing. So `full` means **anyone who can reach this endpoint gets read/write over the entire Cloudflare account the token permits** — including irreversible actions like `DELETE /zones/{id}` (deletes a zone with all its records and settings), API token creation/revocation, and member/Access changes. If you need graduated trust, run a **separate server instance per trust boundary** — its own `MCP_AUTH_TOKEN`, its own Cloudflare token, its own `CLOUDFLARE_API_PASSTHROUGH` — rather than assuming `confirm` provides caller-level authorization it cannot provide.
- **`confirm=true` is set by the model, not by a human.** It is the model asserting intent in its own tool-call JSON, exactly like `cloudflare_delete_dns_record` — but here the blast radius is the whole account, with no snapshot and no undo. Against the realistic threat (a prompt-injected instruction hidden in content the model reads — a DNS TXT record, a fetched web page, an email — telling it to call this tool with `confirm=true`), the flag offers essentially no protection once `full` is set; it only guards against the model calling a write *by accident*. Treat enabling `full` as equivalent to granting root Cloudflare account access to anything that can influence the model's context.
- **JSON endpoints only.** Non-JSON / binary responses (cert or PEM downloads, raw BIND zone-file exports, Worker script source, other binary assets) are out of scope; use the typed tools or the dashboard for those.

The passthrough never returns or logs the token; host pinning restricts every request to `https://api.cloudflare.com/client/v4/…` (absolute URLs, other hosts, protocol-relative `//host`, userinfo, backslashes, and `..` traversal are all rejected before any network call).

## Development

```bash
npm run build    # compile TypeScript → dist/
npm start        # run HTTP server
npm test         # unit tests for the passthrough guards (SSRF path validator + mode resolver)
npm run smoke    # end-to-end client test against the running server
```

Source layout: `src/index.ts` (transports, auth middleware), `src/cloudflare.ts` (API client, zone resolution, formatting), `src/tools.ts` (tool registrations).

## License

[MIT](LICENSE)
