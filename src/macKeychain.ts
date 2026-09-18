import { spawnSync } from "child_process";
import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";
import { CredentialsFile } from "./types";

/**
 * macOS credential storage for Claude Code.
 *
 * On macOS the CLI keeps its OAuth blob in the login Keychain as a generic password,
 * not in .credentials.json — that file is only written when the Keychain refuses the
 * write (locked keychain, SSH session). The item is keyed to the config directory, so
 * a session started with a different CLAUDE_CONFIG_DIR reads a different item.
 *
 * Naming is not part of Claude Code's public contract and has changed between versions,
 * so the service name is probed rather than assumed: newer builds use the hashed name,
 * older ones the unsuffixed legacy name for the default directory.
 */

const SECURITY_BIN = "/usr/bin/security";
const LEGACY_SERVICE = "Claude Code-credentials";
const DEFAULT_TIMEOUT_MS = 10_000;

/** `security` exit code for "the item is not in the keychain". */
const EXIT_ITEM_NOT_FOUND = 44;

export type KeychainFailure = "denied" | "timeout" | "unavailable" | "write-failed";

export class KeychainError extends Error {
  constructor(readonly kind: KeychainFailure, message: string) {
    super(message);
    this.name = "KeychainError";
  }
}

export interface KeychainOptions {
  /** Explicit service name override, for CLI builds that key the item differently. */
  serviceOverride?: string;
  timeoutMs?: number;
}

export function isMacKeychainPlatform(): boolean {
  return process.platform === "darwin";
}

export function defaultClaudeConfigDir(): string {
  return path.join(os.homedir(), ".claude");
}

export function normalizeConfigDir(configDir?: string): string {
  return path.resolve(configDir ?? defaultClaudeConfigDir()).normalize("NFC");
}

export function isDefaultConfigDir(configDir?: string): boolean {
  return normalizeConfigDir(configDir) === normalizeConfigDir(defaultClaudeConfigDir());
}

/** `Claude Code-credentials-<first 8 hex of sha256(config dir)>`. */
export function hashedServiceName(configDir?: string): string {
  const digest = crypto
    .createHash("sha256")
    .update(normalizeConfigDir(configDir))
    .digest("hex")
    .slice(0, 8);
  return `${LEGACY_SERVICE}-${digest}`;
}

/**
 * Service names to try, most specific first.
 *
 * The legacy unsuffixed item belongs to the default config directory only. An isolated
 * profile must never fall back to it: that item is the user's primary login, and reading
 * it would report the wrong account while writing it would overwrite a login the user
 * never asked us to touch.
 */
export function serviceCandidates(configDir?: string, options: KeychainOptions = {}): string[] {
  if (options.serviceOverride?.trim()) {
    return [options.serviceOverride.trim()];
  }
  const hashed = hashedServiceName(configDir);
  return isDefaultConfigDir(configDir) ? [hashed, LEGACY_SERVICE] : [hashed];
}

export function keychainAccount(): string {
  try {
    return os.userInfo().username;
  } catch {
    return process.env.USER ?? "";
  }
}

export interface SecurityResult {
  status: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  spawnFailed: boolean;
}

export type SecurityRunner = (
  args: string[],
  input: string | undefined,
  timeoutMs: number
) => SecurityResult;

/**
 * Replaces the `security` invocation. Tests use this to run the whole backend against an
 * in-memory keychain, on any OS and without touching the real one.
 */
export function setSecurityRunner(next: SecurityRunner | null): void {
  runner = next ?? spawnSecurity;
}

function spawnSecurity(args: string[], input: string | undefined, timeoutMs: number): SecurityResult {
  const res = spawnSync(SECURITY_BIN, args, {
    input,
    encoding: "utf8",
    timeout: timeoutMs,
    windowsHide: true,
  });

  return {
    status: res.status,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
    // A keychain prompt the user never answers shows up as a kill signal, not an exit code.
    timedOut: res.error?.message.includes("ETIMEDOUT") === true || res.signal !== null,
    spawnFailed: res.error !== undefined && res.signal === null,
  };
}

let runner: SecurityRunner = spawnSecurity;

function runSecurity(args: string[], input: string | undefined, timeoutMs: number): SecurityResult {
  return runner(args, input, timeoutMs);
}

function failureFor(res: SecurityResult, action: string): KeychainError {
  if (res.timedOut) {
    return new KeychainError(
      "timeout",
      `The macOS Keychain did not respond while trying to ${action}. ` +
        "If a password prompt is open, answer it and try again."
    );
  }
  if (res.spawnFailed) {
    return new KeychainError("unavailable", `Could not run ${SECURITY_BIN} to ${action}.`);
  }
  const detail = (res.stderr || res.stdout).trim().slice(0, 200);
  return new KeychainError(
    "denied",
    `The macOS Keychain refused to ${action}${detail ? `: ${detail}` : "."}`
  );
}

/**
 * Whether the item exists, without decrypting it. Attribute lookups need no access
 * rights, so this never raises a password prompt and is safe to call on a timer.
 */
export function itemExists(service: string, timeoutMs = DEFAULT_TIMEOUT_MS): boolean {
  const res = runSecurity(
    ["find-generic-password", "-s", service, "-a", keychainAccount()],
    undefined,
    timeoutMs
  );
  return res.status === 0;
}

/** The first candidate service name that actually holds an item, or null. */
export function resolveExistingService(
  configDir?: string,
  options: KeychainOptions = {}
): string | null {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return serviceCandidates(configDir, options).find((s) => itemExists(s, timeoutMs)) ?? null;
}

/**
 * The service name to write to: the existing item if there is one, otherwise the name
 * this platform's CLI is expected to look under.
 */
export function resolveWriteService(configDir?: string, options: KeychainOptions = {}): string {
  const existing = resolveExistingService(configDir, options);
  if (existing) {
    return existing;
  }
  const candidates = serviceCandidates(configDir, options);
  // Seeding a directory that has never been logged into. The default directory keeps the
  // legacy name, which is what shipping CLI builds still use for it.
  return isDefaultConfigDir(configDir) && !options.serviceOverride?.trim()
    ? LEGACY_SERVICE
    : candidates[0];
}

/** Reads and parses the stored blob, or null when no item exists. */
export function readKeychainFile(
  configDir?: string,
  options: KeychainOptions = {}
): CredentialsFile | null {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const service = resolveExistingService(configDir, options);
  if (!service) {
    return null;
  }

  const res = runSecurity(
    ["find-generic-password", "-s", service, "-a", keychainAccount(), "-w"],
    undefined,
    timeoutMs
  );
  if (res.status === EXIT_ITEM_NOT_FOUND) {
    return null;
  }
  if (res.status !== 0) {
    throw failureFor(res, `read "${service}"`);
  }

  try {
    return JSON.parse(res.stdout.trim()) as CredentialsFile;
  } catch {
    return null;
  }
}

/**
 * Longest command line `security -i` accepts on stdin. The interactive parser's buffer is
 * 4 KiB; Claude Code uses this same threshold before falling back to argv.
 */
const INTERACTIVE_LINE_LIMIT = 4032;

/**
 * Writes the blob back, replacing the item in place, and confirms it is readable.
 *
 * This mirrors Claude Code's own writer, because it is the one path proven to survive the
 * `security` tool's quirks:
 *
 * - The value is hex-encoded and passed as `-X` inside a command line fed to `security -i`
 *   on stdin, so it never appears in the process table. The obvious alternative, `-w` with
 *   the value on stdin, is a password prompt that silently truncates at 128 bytes — a real
 *   credential blob is several hundred bytes, and what lands in the keychain is an
 *   unparseable fragment that Claude Code reads as "not logged in".
 * - Blobs whose command line would exceed the interactive limit go on argv instead, again
 *   as Claude Code does. That briefly exposes the hex to `ps`; a normal blob is far below
 *   the limit and only a very large `mcpOAuth` section gets there.
 * - Plain `-U`, never `-A`. The ACL an update leaves behind trusts `/usr/bin/security`,
 *   which is how the CLI, the VS Code extension and this extension all read the item.
 *   `-A` on an update requests a change_acl authorization macOS cannot grant silently: it
 *   stalls for ~20s, is then ignored, and a call killed in the meantime loses the item.
 *
 * The read-back at the end turns any of those failure modes into an error instead of a
 * silent logout.
 */
export function writeKeychainFile(
  file: CredentialsFile,
  configDir?: string,
  options: KeychainOptions = {}
): string {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const service = resolveWriteService(configDir, options);
  const account = keychainAccount();
  const payload = JSON.stringify(file);

  const res = addGenericPassword(service, account, payload, true, timeoutMs);
  if (res.status !== 0) {
    throw failureFor(res, `write "${service}"`);
  }
  if (readBack(service, account, timeoutMs) === payload) {
    return service;
  }

  // An interrupted update can leave no item behind; a plain add recreates it.
  const readd = addGenericPassword(service, account, payload, false, timeoutMs);
  if (readd.status === 0 && readBack(service, account, timeoutMs) === payload) {
    return service;
  }
  throw new KeychainError(
    "write-failed",
    `Wrote "${service}" but could not read the same value back from the macOS Keychain.`
  );
}

function addGenericPassword(
  service: string,
  account: string,
  payload: string,
  update: boolean,
  timeoutMs: number
): SecurityResult {
  const hex = Buffer.from(payload, "utf8").toString("hex");
  const flags = update ? ["-U"] : [];
  const line = `add-generic-password ${flags.join(" ")}${flags.length ? " " : ""}-a "${account}" -s "${service}" -X "${hex}"\n`;

  if (line.length <= INTERACTIVE_LINE_LIMIT) {
    return runSecurity(["-i"], line, timeoutMs);
  }
  return runSecurity(
    ["add-generic-password", ...flags, "-a", account, "-s", service, "-X", hex],
    undefined,
    timeoutMs
  );
}

function readBack(service: string, account: string, timeoutMs: number): string | null {
  const res = runSecurity(
    ["find-generic-password", "-s", service, "-a", account, "-w"],
    undefined,
    timeoutMs
  );
  return res.status === 0 ? res.stdout.replace(/\n$/, "") : null;
}

export function deleteKeychainItem(service: string, timeoutMs = DEFAULT_TIMEOUT_MS): boolean {
  const res = runSecurity(
    ["delete-generic-password", "-s", service, "-a", keychainAccount()],
    undefined,
    timeoutMs
  );
  return res.status === 0;
}
