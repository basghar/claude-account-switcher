import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import {
  KeychainError,
  KeychainOptions,
  defaultClaudeConfigDir,
  isMacKeychainPlatform,
  normalizeConfigDir,
  readKeychainFile,
  resolveExistingService,
  resolveWriteService,
  serviceCandidates,
  writeKeychainFile,
} from "./macKeychain";
import { CredentialsFile } from "./types";

/**
 * Where Claude Code keeps its credentials on this machine.
 *
 * Two implementations: a JSON file (Windows and Linux, where that is the only store the
 * CLI has) and the macOS login Keychain. Everything above this interface works in terms
 * of the credential blob and never branches on platform.
 */
export interface CredentialBackend {
  readonly kind: "file" | "keychain";

  /** Where the credential for this config dir lives, phrased for a user-facing message. */
  describe(configDir?: string): string;

  /** True when a credential is stored. Must not prompt the user. */
  exists(configDir?: string): boolean;

  /** The whole stored blob, so callers can preserve keys they do not understand. */
  read(configDir?: string): CredentialsFile | null;

  /** Replaces the stored blob. */
  write(next: CredentialsFile, configDir?: string): void;

  /**
   * The `.credentials.json` path, when the backend has one. Undefined on backends that
   * do not store credentials in a file, so callers can omit a path-based setting rather
   * than write one that points at nothing.
   */
  credentialsPath(configDir?: string): string | undefined;

  /** Sets the stored credential aside so a fresh login can replace it. */
  moveAside(configDir: string | undefined, reason: string): Promise<string | null>;

  /** Snapshot for undo. One slot, overwritten each time. */
  backup(configDir?: string): Promise<boolean>;
  hasBackup(configDir?: string): Promise<boolean>;
  restore(configDir?: string): Promise<boolean>;
}

function slot(configDir?: string): string {
  return crypto
    .createHash("sha256")
    .update(normalizeConfigDir(configDir))
    .digest("hex")
    .slice(0, 16);
}

/** Windows and Linux, and any machine pointed at an explicit credentials file. */
export class FileCredentialBackend implements CredentialBackend {
  readonly kind = "file";

  constructor(private readonly pathOverride?: () => string | undefined) {}

  credentialsPath(configDir?: string): string {
    if (configDir) {
      return path.join(configDir, ".credentials.json");
    }
    const override = this.pathOverride?.()?.trim();
    return override || path.join(defaultClaudeConfigDir(), ".credentials.json");
  }

  describe(configDir?: string): string {
    return this.credentialsPath(configDir);
  }

  exists(configDir?: string): boolean {
    try {
      return fs.existsSync(this.credentialsPath(configDir));
    } catch {
      return false;
    }
  }

  read(configDir?: string): CredentialsFile | null {
    try {
      return JSON.parse(
        fs.readFileSync(this.credentialsPath(configDir), "utf8")
      ) as CredentialsFile;
    } catch {
      return null;
    }
  }

  write(next: CredentialsFile, configDir?: string): void {
    const p = this.credentialsPath(configDir);
    fs.mkdirSync(path.dirname(p), { recursive: true });

    const tmp = p + ".tmp-" + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(next, null, 2), { encoding: "utf8", mode: 0o600 });
    fs.renameSync(tmp, p);
    try {
      fs.chmodSync(p, 0o600);
    } catch {
      /* best-effort on Windows */
    }
  }

  async moveAside(configDir: string | undefined, reason: string): Promise<string | null> {
    const p = this.credentialsPath(configDir);
    try {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      if (!fs.existsSync(p)) {
        return null;
      }
      const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
      const target = `${p}.${reason}-${stamp}`;
      fs.renameSync(p, target);
      return target;
    } catch (e) {
      throw new Error("Failed to move existing credentials aside: " + (e as Error).message);
    }
  }

  private backupPath(configDir?: string): string {
    return this.credentialsPath(configDir) + ".bak";
  }

  async backup(configDir?: string): Promise<boolean> {
    const p = this.credentialsPath(configDir);
    try {
      if (fs.existsSync(p)) {
        fs.copyFileSync(p, this.backupPath(configDir));
        return true;
      }
    } catch {
      /* ignore */
    }
    return false;
  }

  async hasBackup(configDir?: string): Promise<boolean> {
    try {
      return fs.existsSync(this.backupPath(configDir));
    } catch {
      return false;
    }
  }

  async restore(configDir?: string): Promise<boolean> {
    const bak = this.backupPath(configDir);
    try {
      if (fs.existsSync(bak)) {
        fs.copyFileSync(bak, this.credentialsPath(configDir));
        return true;
      }
    } catch {
      /* ignore */
    }
    return false;
  }
}

/**
 * macOS. The credential is a generic password in the login Keychain, keyed to the config
 * directory. Nothing is written to disk: snapshots for undo go to VS Code's encrypted
 * SecretStorage rather than a plaintext .bak beside a file that does not exist here.
 */
export class KeychainCredentialBackend implements CredentialBackend {
  readonly kind = "keychain";

  constructor(
    private readonly secrets: vscode.SecretStorage,
    private readonly options: () => KeychainOptions = () => ({})
  ) {}

  credentialsPath(): undefined {
    return undefined;
  }

  describe(configDir?: string): string {
    const resolved = resolveExistingService(configDir, this.options());
    const names = resolved ?? serviceCandidates(configDir, this.options()).join(" or ");
    return `macOS Keychain item "${names}"`;
  }

  exists(configDir?: string): boolean {
    try {
      return resolveExistingService(configDir, this.options()) !== null;
    } catch {
      return false;
    }
  }

  read(configDir?: string): CredentialsFile | null {
    return readKeychainFile(configDir, this.options());
  }

  write(next: CredentialsFile, configDir?: string): void {
    writeKeychainFile(next, configDir, this.options());
  }

  /**
   * There is nothing to rename, so the blob is snapshotted and the item emptied. The item
   * itself is left in place: deleting it would drop the ACL that keeps Claude Code from
   * prompting for a keychain password on the next read.
   */
  async moveAside(configDir: string | undefined, reason: string): Promise<string | null> {
    const current = this.read(configDir);
    if (!current) {
      return null;
    }
    const service = resolveWriteService(configDir, this.options());
    const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
    await this.secrets.store(
      `claudeSwitcher.setAside.${slot(configDir)}.${reason}-${stamp}`,
      JSON.stringify(current)
    );
    this.write({} as CredentialsFile, configDir);
    return `${service} (previous value kept in VS Code secret storage as ${reason}-${stamp})`;
  }

  private backupKey(configDir?: string): string {
    return `claudeSwitcher.backup.${slot(configDir)}`;
  }

  async backup(configDir?: string): Promise<boolean> {
    let current: CredentialsFile | null = null;
    try {
      current = this.read(configDir);
    } catch {
      return false;
    }
    if (!current) {
      return false;
    }
    await this.secrets.store(this.backupKey(configDir), JSON.stringify(current));
    return true;
  }

  async hasBackup(configDir?: string): Promise<boolean> {
    return (await this.secrets.get(this.backupKey(configDir))) !== undefined;
  }

  async restore(configDir?: string): Promise<boolean> {
    const raw = await this.secrets.get(this.backupKey(configDir));
    if (!raw) {
      return false;
    }
    try {
      this.write(JSON.parse(raw) as CredentialsFile, configDir);
      return true;
    } catch {
      return false;
    }
  }
}

export type BackendPreference = "auto" | "file" | "keychain";

export function createCredentialBackend(
  secrets: vscode.SecretStorage,
  preference: BackendPreference,
  fileOverride: () => string | undefined,
  keychainOptions: () => KeychainOptions
): CredentialBackend {
  const useKeychain =
    preference === "keychain" || (preference === "auto" && isMacKeychainPlatform());
  return useKeychain
    ? new KeychainCredentialBackend(secrets, keychainOptions)
    : new FileCredentialBackend(fileOverride);
}

export { KeychainError };
