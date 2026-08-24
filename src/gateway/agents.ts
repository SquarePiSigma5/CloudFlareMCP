/**
 * Gateway metadata model + persistence: KEYS (named references to a stored Cloudflare token) and
 * AGENTS (bearer-authenticated callers, each bound to one key).
 *
 * Trust model, at a glance:
 *   - A Key is metadata only. The actual Cloudflare token lives in the SecretStore (store.ts) under
 *     the key's id; this file never sees or stores a Cloudflare token.
 *   - An Agent authenticates with a random 256-bit bearer. We persist ONLY sha256(bearer). The
 *     plaintext bearer is returned exactly once — at createAgent / rotateBearer — and never again,
 *     never persisted, never logged.
 *
 * State is loaded from `${dir}/agents.json` into memory by loadStore(); every mutation writes back
 * atomically at mode 0600.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";

/** A named handle to a Cloudflare token held in the SecretStore. Carries NO secret material. */
export interface Key {
  id: string;
  name: string;
  created_at: string;
}

/**
 * A bearer-authenticated caller bound to one Key.
 *
 * `bearer_sha256` is the sha256 hash of the agent's bearer — the only bearer-derived value ever
 * persisted. It is NOT the plaintext bearer and cannot be reversed into one, but slice-2's admin/MCP
 * serializers must still omit it from any response (per "no stored bearer is ever returned").
 */
export interface Agent {
  id: string;
  name: string;
  bearer_sha256: string;
  key_id: string;
  enabled: boolean;
  created_at: string;
}

interface AgentsState {
  keys: Key[];
  agents: Agent[];
}

/** Result of addKey: the new Key plus the id under which the caller must store its Cloudflare token. */
export interface AddKeyResult {
  key: Key;
  /** The SecretStore id the caller uses: `secretStore.setSecret(secretRef, cloudflareToken)`. */
  secretRef: string;
}

/** Result of createAgent / (bearer half of) rotateBearer: the agent plus its ONE-TIME plaintext bearer. */
export interface CreateAgentResult {
  agent: Agent;
  plaintextBearer: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

/** 128-bit random id as 32 lowercase hex chars. */
function newId(): string {
  return randomBytes(16).toString("hex");
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Atomic 0600 write shared by the persistence layer. Mode 0600 is a create-time openSync flag (never
 * a post-hoc chmod), so agents.json is never momentarily world-readable.
 */
function writeFileAtomic0600(path: string, data: string): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/**
 * In-memory view of the gateway metadata, backed by `${dir}/agents.json`. Construct via loadStore().
 * Every mutating method persists synchronously before returning.
 */
export class AgentStore {
  private readonly path: string;
  private readonly state: AgentsState;

  constructor(path: string, state: AgentsState) {
    this.path = path;
    this.state = state;
  }

  private persist(): void {
    writeFileAtomic0600(this.path, JSON.stringify(this.state, null, 2));
  }

  // ---- Keys ----------------------------------------------------------------

  /**
   * Create a new Key. The caller is responsible for storing the actual Cloudflare token under the
   * returned `secretRef` via a SecretStore — this store never handles the token itself.
   */
  addKey(name: string): AddKeyResult {
    const key: Key = { id: newId(), name, created_at: nowIso() };
    this.state.keys.push(key);
    this.persist();
    return { key: { ...key }, secretRef: key.id };
  }

  listKeys(): Key[] {
    return this.state.keys.map((k) => ({ ...k }));
  }

  /**
   * Delete a Key. REFUSED (throws) while any agent is still bound to it — otherwise those agents
   * would dangle with no resolvable token. The caller deletes the backing secret separately.
   */
  deleteKey(id: string): void {
    const referencing = this.state.agents.filter((a) => a.key_id === id).map((a) => a.name);
    if (referencing.length > 0) {
      throw new Error(
        `Cannot delete key '${id}': it is still referenced by agent(s): ${referencing.join(", ")}. ` +
          "Rebind or delete those agents first.",
      );
    }
    const idx = this.state.keys.findIndex((k) => k.id === id);
    if (idx === -1) throw new Error(`No key with id '${id}'.`);
    this.state.keys.splice(idx, 1);
    this.persist();
  }

  // ---- Agents --------------------------------------------------------------

  /** Create an agent bound to `keyId`, minting a fresh 256-bit bearer (returned once, stored hashed). */
  createAgent(name: string, keyId: string): CreateAgentResult {
    if (!this.state.keys.some((k) => k.id === keyId)) {
      throw new Error(`No key with id '${keyId}' to bind the agent to.`);
    }
    const plaintextBearer = randomBytes(32).toString("hex");
    const agent: Agent = {
      id: newId(),
      name,
      bearer_sha256: sha256Hex(plaintextBearer),
      key_id: keyId,
      enabled: true,
      created_at: nowIso(),
    };
    this.state.agents.push(agent);
    this.persist();
    return { agent: { ...agent }, plaintextBearer };
  }

  /**
   * Resolve an inbound bearer to its ENABLED agent, or undefined.
   *
   * The presented bearer is hashed once, then compared to each enabled agent's stored hash with
   * crypto.timingSafeEqual over equal-length 32-byte buffers — constant-time, so a caller cannot
   * learn a valid bearer by measuring how long a near-miss takes. Disabled agents are skipped
   * entirely (a revoked agent must never authenticate).
   */
  findAgentByBearer(bearer: string): Agent | undefined {
    if (!bearer) return undefined;
    const candidate = Buffer.from(sha256Hex(bearer), "hex"); // always 32 bytes
    for (const a of this.state.agents) {
      if (!a.enabled) continue;
      const stored = Buffer.from(a.bearer_sha256, "hex");
      if (stored.length === candidate.length && timingSafeEqual(stored, candidate)) {
        return { ...a };
      }
    }
    return undefined;
  }

  /** Point an existing agent at a different key. */
  rebindAgent(id: string, keyId: string): Agent {
    const agent = this.state.agents.find((a) => a.id === id);
    if (!agent) throw new Error(`No agent with id '${id}'.`);
    if (!this.state.keys.some((k) => k.id === keyId)) throw new Error(`No key with id '${keyId}'.`);
    agent.key_id = keyId;
    this.persist();
    return { ...agent };
  }

  /** Enable or disable an agent. A disabled agent stops authenticating immediately (see findAgentByBearer). */
  setAgentEnabled(id: string, enabled: boolean): Agent {
    const agent = this.state.agents.find((a) => a.id === id);
    if (!agent) throw new Error(`No agent with id '${id}'.`);
    agent.enabled = enabled;
    this.persist();
    return { ...agent };
  }

  /** Mint a new bearer for an agent, invalidating the old one. Returns the new plaintext bearer once. */
  rotateBearer(id: string): string {
    const agent = this.state.agents.find((a) => a.id === id);
    if (!agent) throw new Error(`No agent with id '${id}'.`);
    const plaintextBearer = randomBytes(32).toString("hex");
    agent.bearer_sha256 = sha256Hex(plaintextBearer);
    this.persist();
    return plaintextBearer;
  }

  listAgents(): Agent[] {
    return this.state.agents.map((a) => ({ ...a }));
  }

  deleteAgent(id: string): void {
    const idx = this.state.agents.findIndex((a) => a.id === id);
    if (idx === -1) throw new Error(`No agent with id '${id}'.`);
    this.state.agents.splice(idx, 1);
    this.persist();
  }
}

/** Load the gateway metadata from `${dir}/agents.json` (empty state if the file does not exist yet). */
export function loadStore(dir: string): AgentStore {
  const path = join(dir, "agents.json");
  let state: AgentsState = { keys: [], agents: [] };
  if (existsSync(path)) {
    const raw = readFileSync(path, "utf8");
    if (raw.trim()) {
      const parsed = JSON.parse(raw) as Partial<AgentsState>;
      state = { keys: parsed.keys ?? [], agents: parsed.agents ?? [] };
    }
  }
  return new AgentStore(path, state);
}
