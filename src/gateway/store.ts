/**
 * Secret storage for gateway mode: the at-rest home for each agent's Cloudflare API token.
 *
 * Two interchangeable backends behind one SecretStore interface:
 *   - KeychainStore     — macOS login keychain via the `security` CLI (OS-managed encryption).
 *   - EncryptedFileStore — a portable AES-256-GCM encrypted JSON file (Linux/servers).
 *
 * selectSecretStore() picks one automatically. The stored VALUE (a Cloudflare token) is never
 * logged, never returned by any admin API, and only ever handed back to the caller that asked for it
 * by id via getSecret().
 */
import { spawnSync } from "node:child_process";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import {
  chmodSync,
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

/** The storage contract every backend implements. `id` is an opaque key handle (see agents.ts). */
export interface SecretStore {
  /** Store (or overwrite) the secret for `id`. */
  setSecret(id: string, value: string): Promise<void>;
  /** Return the secret for `id`, or undefined if there is none. */
  getSecret(id: string): Promise<string | undefined>;
  /** Remove the secret for `id` (idempotent — deleting an absent id is a no-op). */
  deleteSecret(id: string): Promise<void>;
}

// ====================================================================================
// AES-256-GCM primitives (exported for unit testing) — the heart of EncryptedFileStore.
// ====================================================================================

/** scrypt parameters per the security spec: N=2^15, r=8, p=1. maxmem is raised so 128*N*r fits. */
export const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

/** Length of the persisted random salt, in bytes. */
export const SALT_BYTES = 16;
/** AES-GCM IV length, in bytes (96-bit IV is the GCM standard). */
const IV_BYTES = 12;
/** AES-GCM auth-tag length, in bytes. */
const TAG_BYTES = 16;

/** Derive a 32-byte AES-256 key from a passphrase + salt using scrypt(N=2^15, r=8, p=1). */
export function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, SCRYPT_PARAMS);
}

/**
 * Encrypt `plaintext` under `key` (32 bytes) with AES-256-GCM and a fresh random 12-byte IV.
 * Output is base64 of iv(12) | tag(16) | ciphertext — everything decrypt needs, self-describing.
 */
export function gcmEncrypt(key: Buffer, plaintext: string): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

/**
 * Decrypt a base64 iv|tag|ciphertext blob produced by gcmEncrypt.
 *
 * The GCM auth tag is verified by decipher.final(): any tampering with the ciphertext OR the tag, or
 * a wrong key, makes final() THROW rather than return corrupt plaintext. Callers get an exception, so
 * a mutated secrets file can never silently yield a bogus token.
 */
export function gcmDecrypt(key: Buffer, blob: string): string {
  const raw = Buffer.from(blob, "base64");
  if (raw.length < IV_BYTES + TAG_BYTES) {
    throw new Error("Encrypted secret blob is too short to be valid (truncated or corrupt).");
  }
  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
  const ciphertext = raw.subarray(IV_BYTES + TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  // final() throws "Unsupported state or unable to authenticate data" on any tamper / wrong key.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

// ====================================================================================
// Shared filesystem helper: create/replace a file atomically with mode 0600.
// ====================================================================================

/**
 * Write `data` to `path` atomically and with permission bits 0600 from the moment the file exists.
 *
 * The 0600 mode is supplied to openSync's mode argument (a create-time flag), NOT applied afterward
 * with chmod — so there is never an instant where the file is world-readable. "wx" makes the temp
 * write fail rather than clobber a leftover temp; the fsync+rename gives an atomic replace.
 */
function writeFileAtomic0600(path: string, data: string | Buffer): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${basename(path)}.${randomBytes(6).toString("hex")}.tmp`);
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, buf);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/**
 * Ensure the gateway data directory exists and is private (mode 0700). Call ONCE at startup.
 *
 * mkdir is recursive (a no-op when the dir already exists). The chmod that follows is applied
 * UNCONDITIONALLY and best-effort: it tightens even a PRE-EXISTING operator-created dir that a lax
 * umask left at 0755 down to 0700, so the secrets/metadata files inside (themselves created 0600) sit
 * in a directory only the owner can traverse. Any failure — e.g. a non-POSIX filesystem where chmod is
 * meaningless, or insufficient privilege — is swallowed: this is defense-in-depth hardening, not a
 * correctness requirement, and per-file 0600 modes already protect the contents.
 */
export function ensureDataDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* best-effort: ignore on non-POSIX filesystems or when chmod is not permitted */
  }
}

// ====================================================================================
// EncryptedFileStore — AES-256-GCM encrypted JSON map, portable across OSes.
// ====================================================================================

/**
 * Secrets persisted as a JSON map { id -> base64(iv|tag|ciphertext) } at
 * `${dir}/secrets.enc.json` (mode 0600). The AES key is derived once (lazily) from
 * GATEWAY_MASTER_PASSPHRASE + a persisted random 16-byte salt at `${dir}/secrets.salt` (mode 0600).
 * If the passphrase is unset, the FIRST operation that needs the key throws a clear error.
 */
export class EncryptedFileStore implements SecretStore {
  private readonly secretsPath: string;
  private readonly saltPath: string;
  private key?: Buffer;

  constructor(private readonly dir: string) {
    this.secretsPath = join(dir, "secrets.enc.json");
    this.saltPath = join(dir, "secrets.salt");
  }

  /** Derive (and memoize) the AES key. Throws if GATEWAY_MASTER_PASSPHRASE is not set. */
  private getKey(): Buffer {
    if (this.key) return this.key;
    const passphrase = process.env.GATEWAY_MASTER_PASSPHRASE;
    if (!passphrase) {
      throw new Error(
        "GATEWAY_MASTER_PASSPHRASE is not set. The encrypted-file secret store needs it to derive the " +
          "AES-256 key that protects agents' Cloudflare tokens at rest. Set a strong passphrase in the " +
          "server's environment (or switch to the macOS keychain backend) before using gateway mode.",
      );
    }
    this.key = deriveKey(passphrase, this.loadOrCreateSalt());
    return this.key;
  }

  /** Load the persisted salt, creating a fresh random one (0600) on first use. */
  private loadOrCreateSalt(): Buffer {
    if (existsSync(this.saltPath)) {
      const salt = readFileSync(this.saltPath);
      if (salt.length === SALT_BYTES) return salt;
      throw new Error(`Salt file ${this.saltPath} is corrupt (expected ${SALT_BYTES} bytes, got ${salt.length}).`);
    }
    const salt = randomBytes(SALT_BYTES);
    writeFileAtomic0600(this.saltPath, salt);
    return salt;
  }

  private loadMap(): Record<string, string> {
    if (!existsSync(this.secretsPath)) return {};
    const raw = readFileSync(this.secretsPath, "utf8");
    if (!raw.trim()) return {};
    return JSON.parse(raw) as Record<string, string>;
  }

  private saveMap(map: Record<string, string>): void {
    writeFileAtomic0600(this.secretsPath, JSON.stringify(map, null, 2));
  }

  async setSecret(id: string, value: string): Promise<void> {
    const key = this.getKey();
    const map = this.loadMap();
    map[id] = gcmEncrypt(key, value);
    this.saveMap(map);
  }

  async getSecret(id: string): Promise<string | undefined> {
    const map = this.loadMap();
    const blob = map[id];
    if (blob === undefined) return undefined;
    return gcmDecrypt(this.getKey(), blob);
  }

  async deleteSecret(id: string): Promise<void> {
    const map = this.loadMap();
    if (id in map) {
      delete map[id];
      this.saveMap(map);
    }
  }
}

// ====================================================================================
// KeychainStore — macOS login keychain via the `security` CLI.
// ====================================================================================

/** Fixed keychain service name; the per-agent key handle is stored as the account. */
export const KEYCHAIN_SERVICE = "cloudflare-mcp-gateway";
/** macOS `security` exit code for errSecItemNotFound. */
const ERRSEC_ITEM_NOT_FOUND = 44;
const SECURITY_BIN = "/usr/bin/security";

/**
 * macOS-only backend. Each secret is a generic-password item under KEYCHAIN_SERVICE with account=id.
 *
 * RESIDUAL RISK (documented, unavoidable with this CLI): `security add-generic-password -w <secret>`
 * passes the secret value as an argv element. For the brief lifetime of that child process the value
 * is visible in the process table (e.g. `ps auxww`) to other processes owned by the same user. The
 * `security` tool offers no stdin-based password entry for non-interactive scripting, so this cannot
 * be eliminated here — only minimized. We minimize it by (a) using spawnSync with an argv ARRAY (no
 * shell, so the value is never written to shell history or exposed to shell metacharacter handling),
 * (b) confining the value to this single short-lived call, and (c) NEVER logging the argv or the
 * value. Operators who cannot accept the `ps` window should set GATEWAY_SECRET_STORE=file.
 */
export class KeychainStore implements SecretStore {
  async setSecret(id: string, value: string): Promise<void> {
    // -U updates the item in place if it already exists (so setSecret is an upsert).
    // NOTE: `value` appears in this argv only. Do not log `args`.
    const args = ["add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", id, "-w", value];
    const res = spawnSync(SECURITY_BIN, args, { encoding: "utf8" });
    if (res.status !== 0) {
      // security does not echo the -w value in its output, but we still avoid printing stderr here.
      throw new Error(`Keychain add-generic-password failed for id '${id}' (exit ${res.status ?? "signal"}).`);
    }
  }

  async getSecret(id: string): Promise<string | undefined> {
    const res = spawnSync(SECURITY_BIN, ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", id, "-w"], {
      encoding: "utf8",
    });
    if (res.status === ERRSEC_ITEM_NOT_FOUND) return undefined;
    if (res.status !== 0) {
      throw new Error(`Keychain find-generic-password failed for id '${id}' (exit ${res.status ?? "signal"}).`);
    }
    // -w prints the raw password followed by a single trailing newline.
    return res.stdout.replace(/\n$/, "");
  }

  async deleteSecret(id: string): Promise<void> {
    const res = spawnSync(SECURITY_BIN, ["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", id], {
      encoding: "utf8",
    });
    // Not-found is a no-op success (idempotent delete).
    if (res.status !== 0 && res.status !== ERRSEC_ITEM_NOT_FOUND) {
      throw new Error(`Keychain delete-generic-password failed for id '${id}' (exit ${res.status ?? "signal"}).`);
    }
  }
}

// ====================================================================================
// Auto-selector.
// ====================================================================================

/** True when the macOS `security` CLI is available. Cheap file check — no child process spawned. */
function securityCliPresent(): boolean {
  return existsSync(SECURITY_BIN);
}

/**
 * Pick a secret backend: the macOS keychain when we're on darwin, the `security` CLI is present, and
 * the operator has NOT forced GATEWAY_SECRET_STORE=file; otherwise the encrypted file store.
 *
 * `dir` (for the file store) defaults to GATEWAY_DATA_DIR. The keychain path needs no directory, so
 * the GATEWAY_DATA_DIR requirement is enforced only when the file store is actually selected.
 */
export function selectSecretStore(dir?: string): SecretStore {
  const forceFile = process.env.GATEWAY_SECRET_STORE === "file";
  if (!forceFile && process.platform === "darwin" && securityCliPresent()) {
    return new KeychainStore();
  }
  const dataDir = dir ?? process.env.GATEWAY_DATA_DIR;
  if (!dataDir) {
    throw new Error(
      "GATEWAY_DATA_DIR must be set for the encrypted-file secret store (it holds secrets.enc.json and " +
        "secrets.salt). Set GATEWAY_DATA_DIR, or run on macOS with the keychain backend.",
    );
  }
  return new EncryptedFileStore(dataDir);
}
