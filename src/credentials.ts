import * as path from "path";
import { CredentialBackend } from "./credentialBackend";
import {
  hasAccessToken,
  hasUsableOAuthCreds,
  sameNonEmptyToken,
} from "./credentialValidation";
import { defaultClaudeConfigDir } from "./macKeychain";
import { CredentialsFile, OAuthCreds } from "./types";

/**
 * Reads and writes the credential Claude Code authenticates with. Switching accounts =
 * replacing that credential.
 *
 * Storage differs per platform — a JSON file on Windows and Linux, the login Keychain on
 * macOS — and that difference lives entirely behind CredentialBackend. Everything here is
 * policy that applies either way: only write complete credentials, preserve keys we do not
 * own, and never spend a refresh token twice.
 */
export class CredentialsManager {
  constructor(private readonly backend: CredentialBackend) {}

  get backendKind(): "file" | "keychain" {
    return this.backend.kind;
  }

  /** Where the credential lives, for diagnostics and error messages. */
  describe(configDir?: string): string {
    return this.backend.describe(configDir);
  }

  /** The credentials file path, or undefined when the backend does not use one. */
  getCredentialsPath(configDir?: string): string | undefined {
    return this.backend.credentialsPath(configDir);
  }

  getConfigDir(): string {
    const p = this.backend.credentialsPath();
    return p ? path.dirname(p) : defaultClaudeConfigDir();
  }

  exists(configDir?: string): boolean {
    return this.backend.exists(configDir);
  }

  /** Returns the claudeAiOauth object, or null if it is missing or unusable. */
  readCurrent(configDir?: string): OAuthCreds | null {
    let stored: CredentialsFile | null;
    try {
      stored = this.backend.read(configDir);
    } catch {
      // A denied or unanswered keychain prompt reads as "unknown", not "logged out".
      return null;
    }
    const oauth = stored?.claudeAiOauth;
    return hasAccessToken(oauth) ? (oauth as OAuthCreds) : null;
  }

  /**
   * Replaces the stored OAuth credential, leaving every other key in the blob alone —
   * `mcpOAuth` in particular belongs to Claude Code and is not ours to drop.
   */
  writeCreds(creds: OAuthCreds, configDir?: string): void {
    if (!hasUsableOAuthCreds(creds)) {
      throw new Error("Refusing to write incomplete Claude OAuth credentials.");
    }

    let existing: CredentialsFile | null = null;
    try {
      existing = this.backend.read(configDir);
    } catch {
      existing = null;
    }
    this.backend.write({ ...(existing ?? {}), claudeAiOauth: creds } as CredentialsFile, configDir);
  }

  /**
   * Replaces a rotating-token credential only while it still holds the refresh token that
   * was just spent. If Claude Code won the race and already wrote a newer generation, that
   * newer credential is left untouched.
   */
  writeCredsIfCurrent(
    expected: OAuthCreds,
    next: OAuthCreds,
    configDir?: string
  ): boolean {
    const current = this.readCurrent(configDir);
    if (!current || !sameNonEmptyToken(current.refreshToken, expected.refreshToken)) {
      return false;
    }
    this.writeCreds(next, configDir);
    return true;
  }

  /** Snapshots the current credential so a switch can be undone. */
  backupCurrent(configDir?: string): Promise<boolean> {
    return this.backend.backup(configDir);
  }

  hasBackup(configDir?: string): Promise<boolean> {
    return this.backend.hasBackup(configDir);
  }

  restoreBackup(configDir?: string): Promise<boolean> {
    return this.backend.restore(configDir);
  }

  /** Sets the stored credential aside before a forced repair login. */
  moveCredentialsAside(configDir?: string, reason = "backup"): Promise<string | null> {
    return this.backend.moveAside(configDir, reason);
  }
}
