// Unit tests for the passthrough security guards: the host-pinning / SSRF path validator and the
// CLOUDFLARE_API_PASSTHROUGH mode resolver. Uses only Node's built-in test runner (no new deps).
//
// Run against the compiled output:  npm run build && npm test
import test from "node:test";
import assert from "node:assert/strict";
import { validateApiPath, buildWorkerUploadPlan } from "../dist/cloudflare.js";
import {
  resolvePassthroughMode,
  resolveEnvVarAccess,
  parseEnvAllowlist,
  WORKER_SECRET_ENV_DENYLIST,
  parseScriptAllowlist,
  isScriptAllowedForSecret,
  isWorkersDeployEnabled,
} from "../dist/tools.js";

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
  // The specific pair the task calls out.
  assert.deepEqual(resolveEnvVarAccess("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_TOKEN"), { ok: false, reason: "denylisted" });
  assert.deepEqual(resolveEnvVarAccess("MCP_AUTH_TOKEN", "MCP_AUTH_TOKEN"), { ok: false, reason: "denylisted" });
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

console.error("guard-test: all guard assertions registered");
