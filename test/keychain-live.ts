import * as os from "os";
import * as path from "path";
import {
  deleteKeychainItem,
  hashedServiceName,
  keychainAccount,
  readKeychainFile,
  writeKeychainFile,
} from "../src/macKeychain";

/**
 * Exercises the keychain backend against the REAL macOS keychain, on throwaway service
 * names, with payloads the size of real credential blobs. The in-memory fake in smoke.ts
 * cannot catch what `security` actually does with a 600-byte value, and the first release
 * of this backend shipped a truncation bug for exactly that reason.
 *
 * Opt-in (`npm run test:keychain`), macOS only. Never touches Claude Code's own items.
 */
let failures = 0;
function check(name: string, cond: boolean): void {
  console.log((cond ? "  PASS" : "  FAIL") + " - " + name);
  if (!cond) failures++;
}

if (process.platform !== "darwin") {
  console.log("keychain-live: not macOS, skipping");
  process.exit(0);
}

const configDir = path.join(os.tmpdir(), `cas-keychain-live-${process.pid}`);
const service = hashedServiceName(configDir);
console.log(`keychain-live: service "${service}" account "${keychainAccount()}"`);

const tokenOf = (n: number, seed: string) => `sk-ant-${seed}-` + seed.repeat(Math.ceil(n / seed.length)).slice(0, n);
const blob = (n: number) => ({
  claudeAiOauth: {
    accessToken: tokenOf(n, "a1"),
    refreshToken: tokenOf(n, "r2"),
    expiresAt: 1789735946903,
    refreshTokenExpiresAt: 1821271946903,
    scopes: ["user:file_upload", "user:inference", "user:mcp_servers", "user:profile"],
    subscriptionType: "max",
    rateLimitTier: "default_claude_max_5x",
  },
  mcpOAuth: { keep: "me" },
});

try {
  check("throwaway item does not exist yet", readKeychainFile(configDir) === null);

  for (const n of [95, 600, 1500]) {
    const value = blob(n);
    writeKeychainFile(value, configDir);
    const back = readKeychainFile(configDir);
    check(
      `round-trip with ${JSON.stringify(value).length}-byte blob (security -i)`,
      JSON.stringify(back) === JSON.stringify(value)
    );
  }

  const large = blob(2500);
  writeKeychainFile(large, configDir);
  check(
    `round-trip with ${JSON.stringify(large).length}-byte blob (argv fallback)`,
    JSON.stringify(readKeychainFile(configDir)) === JSON.stringify(large)
  );

  const started = Date.now();
  writeKeychainFile(blob(600), configDir);
  check("an update completes quickly (no ACL authorization stall)", Date.now() - started < 2000);
} finally {
  const removed = deleteKeychainItem(service);
  check("throwaway item cleaned up", removed && readKeychainFile(configDir) === null);
}

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
