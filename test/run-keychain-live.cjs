const { execFileSync } = require("child_process");
const esbuild = require("esbuild");

esbuild.buildSync({
  entryPoints: ["test/keychain-live.ts"],
  bundle: true,
  platform: "node",
  format: "cjs",
  alias: { vscode: "./test/vscode-stub.js" },
  outfile: "out/keychain-live.cjs",
  logLevel: "warning",
});

execFileSync(process.execPath, ["out/keychain-live.cjs"], { stdio: "inherit" });
