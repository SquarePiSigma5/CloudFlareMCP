// Smoke test: connects to the running HTTP server with a real MCP client,
// lists tools, and calls cloudflare_verify_token.
//
// Usage:  MCP_URL=http://127.0.0.1:8787/mcp MCP_AUTH_TOKEN=... npm run smoke
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const url = new URL(process.env.MCP_URL ?? "http://127.0.0.1:8787/mcp");
const headers = process.env.MCP_AUTH_TOKEN
  ? { Authorization: `Bearer ${process.env.MCP_AUTH_TOKEN}` }
  : {};

const transport = new StreamableHTTPClientTransport(url, { requestInit: { headers } });
const client = new Client({ name: "smoke-test", version: "1.0.0" });

await client.connect(transport);
const { tools } = await client.listTools();
console.log(`Connected to ${url} — ${tools.length} tools:`);
for (const t of tools) console.log(`  - ${t.name}`);

const res = await client.callTool({ name: "cloudflare_verify_token", arguments: {} });
console.log("\ncloudflare_verify_token →");
console.log(res.content?.[0]?.text ?? JSON.stringify(res));

await client.close();
