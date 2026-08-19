// Unit tests for the passthrough security guards: the host-pinning / SSRF path validator and the
// CLOUDFLARE_API_PASSTHROUGH mode resolver. Uses only Node's built-in test runner (no new deps).
//
// Run against the compiled output:  npm run build && npm test
import test from "node:test";
import assert from "node:assert/strict";
import { validateApiPath } from "../dist/cloudflare.js";
import { resolvePassthroughMode } from "../dist/tools.js";

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

console.error("guard-test: all guard assertions registered");
