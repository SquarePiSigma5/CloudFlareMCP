// Unit tests for the passthrough security guards: the host-pinning / SSRF path validator and the
// CLOUDFLARE_API_PASSTHROUGH mode resolver. Uses only Node's built-in test runner (no new deps).
//
// Run against the compiled output:  npm run build && npm test
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { mkdtempSync, statSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { validateApiPath, buildWorkerUploadPlan, apiToken } from "../dist/cloudflare.js";
import {
  resolvePassthroughMode,
  resolveEnvVarAccess,
  parseEnvAllowlist,
  WORKER_SECRET_ENV_DENYLIST,
  parseScriptAllowlist,
  isScriptAllowedForSecret,
  isWorkersDeployEnabled,
} from "../dist/tools.js";
import { gatewayEnabled, runWithToken } from "../dist/gateway/context.js";
import { deriveKey, gcmEncrypt, gcmDecrypt, EncryptedFileStore, selectSecretStore } from "../dist/gateway/store.js";
import { loadStore } from "../dist/gateway/agents.js";
import {
  hostHeaderIsLocal,
  originIsLocal,
  extractBearer,
  constantTimeEquals,
  serializeKey,
  serializeAgent,
  buildConnectorSnippet,
  resolveAdminPassword,
} from "../dist/gateway/admin.js";

// --- SSRF / host-pinning: every named bypass vector must be rejected before any network call. ---
const rejected = [
  "https://evil.com/x", // absolute URL — must not override the base
  "http://evil.com/x",
  "//evil.com/x", // protocol-relative host
  "/client/v4/../../../etc", // .. traversal escaping the v4 base
  "/../admin",
  "/zones\\..\\..", // backslashes
  "zones", // missing leading slash
  "", // empty
  "/zones\nX", // control char / whitespace
  "/ zones", // whitespace
];
for (const p of rejected) {
  test(`rejects ${JSON.stringify(p)}`, () => {
    assert.throws(() => validateApiPath(p), /API path/);
  });
}

// A userinfo attempt cannot introduce a new authority because the authority is fixed by API_BASE;
// it stays a harmless path under the pinned origin. Assert the origin is still Cloudflare.
test("userinfo-looking path stays pinned to the Cloudflare origin", () => {
  const url = validateApiPath("/@evil.com/zones");
  assert.equal(url.origin, "https://api.cloudflare.com");
  assert.ok(url.pathname.startsWith("/client/v4/"));
});

// --- Valid relative paths are accepted and resolve under the pinned base. ---
for (const p of ["/zones", "/user/tokens/verify", "/zones/abc/purge_cache", "/accounts/xyz/members"]) {
  test(`accepts ${JSON.stringify(p)}`, () => {
    const url = validateApiPath(p);
    assert.equal(url.origin, "https://api.cloudflare.com");
    assert.ok(url.pathname.startsWith("/client/v4/"));
  });
}

// --- Mode resolver: reads-on default. Only an EXACT "off"/"full" leaves the "read" default;
// everything else (unset, "", typos, wrong case, whitespace-padded) resolves to "read".
// Covering off→off AND full→full AND unset→read makes this suite non-vacuous: a constant
// implementation cannot satisfy all three.
test("resolvePassthroughMode: exact off/full change the default read", () => {
  assert.equal(resolvePassthroughMode("full"), "full");
  assert.equal(resolvePassthroughMode("off"), "off");
});
test("resolvePassthroughMode: unset and unrecognized resolve to the 'read' default", () => {
  const readCases = [
    undefined, // unset env var
    "", // empty
    "read", // explicit read
    "READ", // wrong case
    "anything", // unrecognized value
    "Full", // wrong case → never 'full'
    "full ", // trailing whitespace → never 'full'
    " full", // leading whitespace → never 'full'
    "Off", // wrong case → never 'off'
    "OFF ", // wrong case + whitespace → never 'off'
  ];
  for (const raw of readCases) {
    assert.equal(resolvePassthroughMode(raw), "read", `expected 'read' for ${JSON.stringify(raw)}`);
  }
});

// --- Worker-secret env allowlist/denylist resolver (Feature A). Exact-string, CASE-SENSITIVE match;
// the only normalization is trimming list entries. Fail-closed: empty allowlist ⇒ deny-all. ---

test("resolveEnvVarAccess: empty/unset allowlist denies ALL (feature disabled)", () => {
  for (const raw of [undefined, "", "   ", " , , "]) {
    const d = resolveEnvVarAccess("MY_SERVICE_API_KEY", raw);
    assert.equal(d.ok, false);
    assert.equal(d.reason, "disabled", `expected 'disabled' for ${JSON.stringify(raw)}`);
  }
});

test("resolveEnvVarAccess: denylisted names are rejected even when allowlisted", () => {
  for (const name of WORKER_SECRET_ENV_DENYLIST) {
    // Put the denylisted name IN the allowlist alongside a benign one — deny must still win.
    const d = resolveEnvVarAccess(name, `MY_SERVICE_API_KEY, ${name}`);
    assert.equal(d.ok, false);
    assert.equal(d.reason, "denylisted", `expected 'denylisted' for ${name}`);
  }
  // The specific single-tenant trust secrets.
  assert.deepEqual(resolveEnvVarAccess("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"), { ok: false, reason: "denylisted" });
  assert.deepEqual(resolveEnvVarAccess("MCP_AUTH_TOKEN", "MCP_AUTH_TOKEN"), { ok: false, reason: "denylisted" });
  // Gateway-mode trust secrets must ALSO be hard-denied even if an operator allowlists them: the master
  // passphrase decrypts every tenant's stored token, and ADMIN_PASSWORD is full admin-panel access.
  // Assert membership first so a future removal from the list fails here, not just silently.
  assert.ok(WORKER_SECRET_ENV_DENYLIST.includes("GATEWAY_MASTER_PASSPHRASE"), "GATEWAY_MASTER_PASSPHRASE must be denylisted");
  assert.ok(WORKER_SECRET_ENV_DENYLIST.includes("ADMIN_PASSWORD"), "ADMIN_PASSWORD must be denylisted");
  assert.deepEqual(resolveEnvVarAccess("GATEWAY_MASTER_PASSPHRASE", "GATEWAY_MASTER_PASSPHRASE"), { ok: false, reason: "denylisted" });
  assert.deepEqual(resolveEnvVarAccess("ADMIN_PASSWORD", "ADMIN_PASSWORD"), { ok: false, reason: "denylisted" });
  // Non-vacuous: the same allowlist that denies these WOULD permit a benign, non-denylisted name.
  assert.deepEqual(resolveEnvVarAccess("MY_SERVICE_API_KEY", "MY_SERVICE_API_KEY, GATEWAY_MASTER_PASSPHRASE, ADMIN_PASSWORD"), { ok: true });
});

test("resolveEnvVarAccess: exact allowlisted name is permitted", () => {
  assert.deepEqual(resolveEnvVarAccess("MY_SERVICE_API_KEY", "MY_SERVICE_API_KEY"), { ok: true });
  // Whitespace around entries is trimmed, so a padded list still matches.
  assert.deepEqual(resolveEnvVarAccess("MY_SERVICE_API_KEY", "  FOO , MY_SERVICE_API_KEY ,BAR "), { ok: true });
});

test("resolveEnvVarAccess: a name not in the allowlist is refused (not vacuous — allow vs deny differ)", () => {
  const d = resolveEnvVarAccess("OTHER_KEY", "MY_SERVICE_API_KEY,FOO");
  assert.equal(d.ok, false);
  assert.equal(d.reason, "not-allowlisted");
});

test("resolveEnvVarAccess: matching is CASE-SENSITIVE (same name, different case = non-match)", () => {
  // 'my_service_api_key' must NOT match an allowlist of 'MY_SERVICE_API_KEY'.
  const d = resolveEnvVarAccess("my_service_api_key", "MY_SERVICE_API_KEY");
  assert.equal(d.ok, false);
  assert.equal(d.reason, "not-allowlisted");
});

test("parseEnvAllowlist: trims, drops empties, preserves exact names", () => {
  assert.deepEqual(parseEnvAllowlist("  A , B ,, C , "), ["A", "B", "C"]);
  assert.deepEqual(parseEnvAllowlist(undefined), []);
  assert.deepEqual(parseEnvAllowlist(""), []);
});

// --- Worker-secret SCRIPT allowlist (Feature A, critique #2). Empty ⇒ NO script may receive a secret. ---

test("isScriptAllowedForSecret: empty/unset allowlist permits NO script (fail-closed)", () => {
  for (const raw of [undefined, "", "  "]) {
    assert.equal(isScriptAllowedForSecret("my-worker", raw), false, `expected false for ${JSON.stringify(raw)}`);
  }
});

test("isScriptAllowedForSecret: exact, case-sensitive, trimmed membership", () => {
  assert.equal(isScriptAllowedForSecret("my-worker", "my-worker"), true);
  assert.equal(isScriptAllowedForSecret("my-worker", " a , my-worker , b "), true);
  assert.equal(isScriptAllowedForSecret("other-worker", "my-worker"), false);
  assert.equal(isScriptAllowedForSecret("My-Worker", "my-worker"), false); // case-sensitive
});

test("parseScriptAllowlist: trims and drops empties", () => {
  assert.deepEqual(parseScriptAllowlist(" x , y ,, z "), ["x", "y", "z"]);
});

// --- Feature B deploy opt-in: strict, exact "true" only (fail-closed). ---

test("isWorkersDeployEnabled: only an exact 'true' enables; anything else is disabled", () => {
  assert.equal(isWorkersDeployEnabled("true"), true);
  for (const raw of [undefined, "", "TRUE", "True", " true", "true ", "1", "yes", "on"]) {
    assert.equal(isWorkersDeployEnabled(raw), false, `expected false for ${JSON.stringify(raw)}`);
  }
});

// --- Feature B multipart metadata builder: esm vs service_worker shape + optional fields. ---

test("buildWorkerUploadPlan (esm): main_module metadata, module Content-Type, filename, part naming", () => {
  const plan = buildWorkerUploadPlan({ mainModule: "worker.js", moduleType: "esm" });
  assert.deepEqual(plan.metadata, { main_module: "worker.js" });
  assert.equal(plan.scriptField, "worker.js");
  assert.equal(plan.parts.length, 2);
  const meta = plan.parts.find((p) => p.role === "metadata");
  const scriptPart = plan.parts.find((p) => p.role === "script");
  assert.deepEqual(meta, { role: "metadata", field: "metadata", contentType: "application/json" });
  assert.equal(scriptPart.field, "worker.js");
  assert.equal(scriptPart.contentType, "application/javascript+module");
  assert.equal(scriptPart.filename, "worker.js");
  // esm must NOT use body_part.
  assert.equal("body_part" in plan.metadata, false);
});

test("buildWorkerUploadPlan (service_worker): body_part metadata + application/javascript type", () => {
  const plan = buildWorkerUploadPlan({ mainModule: "script", moduleType: "service_worker" });
  assert.deepEqual(plan.metadata, { body_part: "script" });
  assert.equal(plan.scriptField, "script");
  const scriptPart = plan.parts.find((p) => p.role === "script");
  assert.equal(scriptPart.contentType, "application/javascript");
  assert.equal(scriptPart.field, "script");
  // service_worker must NOT use main_module.
  assert.equal("main_module" in plan.metadata, false);
});

test("buildWorkerUploadPlan: compatibility_date/flags/bindings included only when provided", () => {
  const bindings = [{ type: "plain_text", name: "MSG", text: "hi" }];
  const full = buildWorkerUploadPlan({
    mainModule: "worker.js",
    moduleType: "esm",
    compatibilityDate: "2024-11-01",
    compatibilityFlags: ["nodejs_compat"],
    bindings,
  });
  assert.equal(full.metadata.compatibility_date, "2024-11-01");
  assert.deepEqual(full.metadata.compatibility_flags, ["nodejs_compat"]);
  assert.deepEqual(full.metadata.bindings, bindings);

  // Absent / empty optional fields are omitted entirely (not set to undefined/empty).
  const minimal = buildWorkerUploadPlan({ mainModule: "worker.js", moduleType: "esm", compatibilityFlags: [], bindings: [] });
  assert.equal("compatibility_date" in minimal.metadata, false);
  assert.equal("compatibility_flags" in minimal.metadata, false);
  assert.equal("bindings" in minimal.metadata, false);
});

// ====================================================================================
// Gateway mode (slice 1) — hermetic tests: temp dirs, GATEWAY_SECRET_STORE=file, a test
// passphrase; the real macOS keychain is NEVER touched.
// ====================================================================================

function mkTmp(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}
function withEnv(name, value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, name);
  const old = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  try {
    return fn();
  } finally {
    if (had) process.env[name] = old;
    else delete process.env[name];
  }
}

// --- AES-256-GCM: round-trip, tamper-detection, wrong-key, and the scrypt KDF. ---

test("gcm: encrypt→decrypt round-trip returns the original plaintext", () => {
  const key = randomBytes(32);
  const pt = "cf-token-value-with-unicode-\u{1F510}-and-symbols-#%&";
  assert.equal(gcmDecrypt(key, gcmEncrypt(key, pt)), pt);
});

test("gcm: tampering the ciphertext OR the tag makes decrypt throw (auth tag verified)", () => {
  const key = randomBytes(32);
  const blob = gcmEncrypt(key, "sensitive-secret");
  // Flip a ciphertext byte (last byte of iv|tag|ciphertext).
  const ct = Buffer.from(blob, "base64");
  ct[ct.length - 1] ^= 0xff;
  assert.throws(() => gcmDecrypt(key, ct.toString("base64")));
  // Flip a byte inside the 16-byte tag (bytes 12..28).
  const tg = Buffer.from(blob, "base64");
  tg[13] ^= 0xff;
  assert.throws(() => gcmDecrypt(key, tg.toString("base64")));
});

test("gcm: a wrong key fails authentication (cannot decrypt another key's blob)", () => {
  const blob = gcmEncrypt(randomBytes(32), "x");
  assert.throws(() => gcmDecrypt(randomBytes(32), blob));
});

test("deriveKey: scrypt(N=2^15,r=8,p=1) yields a deterministic 32-byte key; salt changes it", () => {
  const salt = randomBytes(16);
  const k1 = deriveKey("passphrase", salt);
  const k2 = deriveKey("passphrase", salt);
  assert.equal(k1.length, 32);
  assert.ok(k1.equals(k2), "same passphrase+salt must derive the same key");
  assert.ok(!k1.equals(deriveKey("passphrase", randomBytes(16))), "a different salt must derive a different key");
});

// --- EncryptedFileStore: set→get→delete, 0600 file mode, plaintext never on disk, passphrase gate. ---

test("EncryptedFileStore: round-trip + 0600 modes + ciphertext never contains the plaintext", async () => {
  const dir = mkTmp("cfmcp-store-");
  try {
    await withEnv("GATEWAY_MASTER_PASSPHRASE", "unit-test-passphrase-do-not-reuse", async () => {
      const store = new EncryptedFileStore(dir);
      await store.setSecret("key-1", "cf-token-abc123");
      assert.equal(await store.getSecret("key-1"), "cf-token-abc123");

      const secretsPath = join(dir, "secrets.enc.json");
      assert.equal(statSync(secretsPath).mode & 0o777, 0o600, "secrets file must be mode 0600");
      assert.equal(statSync(join(dir, "secrets.salt")).mode & 0o777, 0o600, "salt file must be mode 0600");

      const raw = readFileSync(secretsPath, "utf8");
      assert.ok(!raw.includes("cf-token-abc123"), "plaintext secret must never appear in the encrypted file");

      await store.deleteSecret("key-1");
      assert.equal(await store.getSecret("key-1"), undefined);
      await store.deleteSecret("key-1"); // idempotent
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("EncryptedFileStore: throws a clear error when GATEWAY_MASTER_PASSPHRASE is unset", async () => {
  const dir = mkTmp("cfmcp-store-");
  try {
    await withEnv("GATEWAY_MASTER_PASSPHRASE", undefined, async () => {
      const store = new EncryptedFileStore(dir);
      await assert.rejects(() => store.setSecret("x", "y"), /GATEWAY_MASTER_PASSPHRASE/);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("selectSecretStore: GATEWAY_SECRET_STORE=file selects the encrypted file backend", () => {
  withEnv("GATEWAY_SECRET_STORE", "file", () => {
    const store = selectSecretStore("/tmp/does-not-need-to-exist-for-construction");
    assert.ok(store instanceof EncryptedFileStore);
  });
});

// --- agents.ts: sha256 bearer hashing, findAgentByBearer (match / no-match / disabled), deleteKey guard. ---

test("agents: createAgent → findAgentByBearer matches; wrong bearer and disabled agents do NOT match", () => {
  const dir = mkTmp("cfmcp-agents-");
  try {
    const store = loadStore(dir);
    const { key, secretRef } = store.addKey("prod-cf-token");
    assert.equal(secretRef, key.id, "secretRef is the key id the caller stores the secret under");

    const { agent, plaintextBearer } = store.createAgent("agent-a", key.id);
    assert.equal(plaintextBearer.length, 64, "bearer is 32 random bytes as hex (256 bits)");

    // Match.
    assert.equal(store.findAgentByBearer(plaintextBearer)?.id, agent.id);
    // No-match.
    assert.equal(store.findAgentByBearer("nope"), undefined);
    assert.equal(store.findAgentByBearer(randomBytes(32).toString("hex")), undefined);
    // Disabled agents never authenticate.
    store.setAgentEnabled(agent.id, false);
    assert.equal(store.findAgentByBearer(plaintextBearer), undefined);
    // Re-enabling restores the match.
    store.setAgentEnabled(agent.id, true);
    assert.equal(store.findAgentByBearer(plaintextBearer)?.id, agent.id);

    // The plaintext bearer is NEVER persisted — only its sha256 is.
    const persisted = readFileSync(join(dir, "agents.json"), "utf8");
    assert.ok(!persisted.includes(plaintextBearer), "plaintext bearer must never be written to disk");
    assert.ok(persisted.includes(createHash("sha256").update(plaintextBearer).digest("hex")), "sha256(bearer) is stored");
    assert.equal(statSync(join(dir, "agents.json")).mode & 0o777, 0o600, "agents.json must be mode 0600");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("agents: rotateBearer invalidates the old bearer and yields a working new one", () => {
  const dir = mkTmp("cfmcp-agents-");
  try {
    const store = loadStore(dir);
    const { key } = store.addKey("k");
    const { agent, plaintextBearer } = store.createAgent("a", key.id);
    const rotated = store.rotateBearer(agent.id);
    assert.notEqual(rotated, plaintextBearer);
    assert.equal(store.findAgentByBearer(plaintextBearer), undefined, "old bearer no longer authenticates");
    assert.equal(store.findAgentByBearer(rotated)?.id, agent.id, "new bearer authenticates");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("agents: deleteKey is refused while an agent references it, allowed once the agent is gone", () => {
  const dir = mkTmp("cfmcp-agents-");
  try {
    const store = loadStore(dir);
    const { key } = store.addKey("shared-key");
    const { agent } = store.createAgent("bound-agent", key.id);
    assert.throws(() => store.deleteKey(key.id), /still referenced|Cannot delete key/i);
    store.deleteAgent(agent.id);
    store.deleteKey(key.id); // now permitted
    assert.equal(store.listKeys().length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("agents: state persists to disk and reloads (fresh loadStore sees prior keys/agents)", () => {
  const dir = mkTmp("cfmcp-agents-");
  try {
    const s1 = loadStore(dir);
    const { key } = s1.addKey("k");
    const { agent, plaintextBearer } = s1.createAgent("a", key.id);
    const s2 = loadStore(dir); // re-read from disk, no shared memory
    assert.equal(s2.listKeys().length, 1);
    assert.equal(s2.findAgentByBearer(plaintextBearer)?.id, agent.id);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- apiToken(): gateway mode fails closed to the ALS token (NO env fallback); single-tenant unchanged. ---

test("apiToken: gateway mode uses the ALS token and throws without one — never the env token", () => {
  withEnv("GATEWAY_ENABLE", "true", () => {
    assert.equal(gatewayEnabled(), true);
    // Bound context → returns exactly that token.
    const bound = runWithToken({ cloudflareToken: "tenant-A-token", agentName: "A" }, () => apiToken());
    assert.equal(bound, "tenant-A-token");
    // No context → throws (fails closed), does NOT fall back.
    assert.throws(() => apiToken(), /gateway mode/i);
    // Even with a global env token present, gateway mode ignores it entirely.
    withEnv("CLOUDFLARE_API_TOKEN", "GLOBAL-MUST-NOT-BE-USED", () => {
      assert.throws(() => apiToken(), /gateway mode/i, "env token must NOT be used as a fallback in gateway mode");
      const b = runWithToken({ cloudflareToken: "tenant-B-token", agentName: "B" }, () => apiToken());
      assert.equal(b, "tenant-B-token");
    });
  });
});

test("apiToken: single-tenant mode returns the env token, and throws when it is unset", () => {
  withEnv("GATEWAY_ENABLE", undefined, () => {
    assert.equal(gatewayEnabled(), false);
    withEnv("CLOUDFLARE_API_TOKEN", "single-tenant-token", () => {
      assert.equal(apiToken(), "single-tenant-token");
    });
    withEnv("CLOUDFLARE_API_TOKEN", undefined, () => {
      assert.throws(() => apiToken(), /CLOUDFLARE_API_TOKEN is not set/);
    });
  });
});

// ====================================================================================
// Gateway admin panel (slice 2) — pure helpers: localhost guards, constant-time password,
// serialization that never leaks a bearer, connector snippet, and password resolution.
// ====================================================================================

test("admin hostHeaderIsLocal: accepts loopback (any port / IPv6), rejects everything else + missing", () => {
  for (const h of ["127.0.0.1", "127.0.0.1:8788", "localhost", "localhost:8788", "[::1]", "[::1]:8788", "LOCALHOST:80"]) {
    assert.equal(hostHeaderIsLocal(h), true, `expected local for ${JSON.stringify(h)}`);
  }
  for (const h of [undefined, "", "evil.example", "evil.example:8788", "10.0.0.5", "example.com", "127.0.0.1.evil.com"]) {
    assert.equal(hostHeaderIsLocal(h), false, `expected non-local for ${JSON.stringify(h)}`);
  }
});

test("admin originIsLocal: absent Origin allowed; loopback allowed; cross-origin and 'null' refused", () => {
  assert.equal(originIsLocal(undefined), true); // no Origin header → not a cross-origin request
  for (const o of ["http://localhost:8788", "http://127.0.0.1:8788", "https://localhost", "http://[::1]:8788"]) {
    assert.equal(originIsLocal(o), true, `expected local for ${JSON.stringify(o)}`);
  }
  for (const o of ["null", "", "http://evil.example", "https://evil.example:8788", "http://attacker.test"]) {
    assert.equal(originIsLocal(o), false, `expected refused for ${JSON.stringify(o)}`);
  }
});

test("admin extractBearer: parses 'Bearer <t>' (case-insensitive scheme), else undefined", () => {
  assert.equal(extractBearer("Bearer abc123"), "abc123");
  assert.equal(extractBearer("bearer abc123"), "abc123");
  assert.equal(extractBearer("  Bearer   xyz  "), "xyz");
  for (const h of [undefined, "", "abc123", "Basic abc", "Bearer"]) {
    assert.equal(extractBearer(h), undefined, `expected undefined for ${JSON.stringify(h)}`);
  }
});

test("admin constantTimeEquals: true only on exact match; different lengths do not throw", () => {
  const secret = randomBytes(32).toString("hex");
  assert.equal(constantTimeEquals(secret, secret), true);
  assert.equal(constantTimeEquals(secret, secret + "x"), false);
  assert.equal(constantTimeEquals("short", "a-much-longer-value"), false); // no throw despite unequal lengths
  assert.equal(constantTimeEquals("", ""), true);
});

test("admin serializeKey/serializeAgent: never expose a secret or the stored bearer hash", () => {
  const k = { id: "k1", name: "prod", created_at: "2026-01-01T00:00:00Z" };
  assert.deepEqual(serializeKey(k), { id: "k1", name: "prod", created_at: "2026-01-01T00:00:00Z" });

  const agent = {
    id: "a1",
    name: "agent-a",
    bearer_sha256: "DEADBEEF-this-must-never-appear",
    key_id: "k1",
    enabled: true,
    created_at: "2026-01-02T00:00:00Z",
  };
  const out = serializeAgent(agent, "prod");
  assert.deepEqual(out, { id: "a1", name: "agent-a", key_id: "k1", key_name: "prod", enabled: true, created_at: "2026-01-02T00:00:00Z" });
  assert.equal("bearer_sha256" in out, false, "bearer_sha256 must not be serialized");
  assert.ok(!JSON.stringify(out).includes("DEADBEEF"), "the stored bearer hash must never leak");
  // A dangling key reference serializes key_name as null, not a crash.
  assert.equal(serializeAgent(agent, undefined).key_name, null);
});

test("admin buildConnectorSnippet: embeds bearer + /mcp url; placeholder host when no public url", () => {
  const snip = buildConnectorSnippet("Claude Desktop", "BEARER-XYZ", "https://cf.example.com");
  const cfg = JSON.parse(snip);
  const entry = cfg.mcpServers["cloudflare-claude-desktop"];
  assert.equal(entry.url, "https://cf.example.com/mcp");
  assert.equal(entry.headers.Authorization, "Bearer BEARER-XYZ");
  // No public url → obvious placeholder host, still a valid single /mcp path.
  const ph = JSON.parse(buildConnectorSnippet("a", "B", undefined));
  assert.equal(ph.mcpServers["cloudflare-a"].url, "https://<your-mcp-host>/mcp");
  // A public url already ending in /mcp is not doubled.
  const nd = JSON.parse(buildConnectorSnippet("a", "B", "https://h/mcp"));
  assert.equal(nd.mcpServers["cloudflare-a"].url, "https://h/mcp");
});

test("admin resolveAdminPassword: uses ADMIN_PASSWORD when set; generates 64-hex and logs once when unset", () => {
  withEnv("ADMIN_PASSWORD", "a-strong-chosen-password", () => {
    // >= 16 chars → no generation message AND no weak-password warning.
    let logged = 0;
    assert.equal(resolveAdminPassword(() => logged++), "a-strong-chosen-password");
    assert.equal(logged, 0, "no message when a strong ADMIN_PASSWORD is set");
  });
  withEnv("ADMIN_PASSWORD", undefined, () => {
    let logged = 0;
    const pw = resolveAdminPassword(() => logged++);
    assert.match(pw, /^[0-9a-f]{64}$/, "generated password is 32 random bytes as hex");
    assert.equal(logged, 1, "the generated password is announced exactly once");
  });
  withEnv("ADMIN_PASSWORD", "   ", () => {
    // whitespace-only is treated as unset → generated
    const pw = resolveAdminPassword(() => {});
    assert.match(pw, /^[0-9a-f]{64}$/);
  });
});

// --- FIX 3: a short OPERATOR-set ADMIN_PASSWORD earns exactly one weakness warning; the password
// value is never logged; a >= 16-char password is used silently. Non-vacuous: warn vs no-warn differ. ---
test("admin resolveAdminPassword: warns ONCE on a short operator password without echoing it", () => {
  withEnv("ADMIN_PASSWORD", "pw123", () => {
    const msgs = [];
    const pw = resolveAdminPassword((...a) => msgs.push(a.join(" ")));
    assert.equal(pw, "pw123", "a short operator password is still used verbatim");
    assert.equal(msgs.length, 1, "exactly one warning for a short operator password");
    assert.match(msgs[0], /weak/i, "the warning explains the password is weak");
    assert.ok(!msgs[0].includes("pw123"), "the password VALUE must never be logged");
  });
  // Boundary: exactly 16 chars is NOT weak (< 16 only), so no warning.
  withEnv("ADMIN_PASSWORD", "0123456789abcdef", () => {
    let logged = 0;
    assert.equal(resolveAdminPassword(() => logged++), "0123456789abcdef");
    assert.equal(logged, 0, "a 16-char password is at the threshold and not warned");
  });
});

console.error("guard-test: all guard assertions registered");
