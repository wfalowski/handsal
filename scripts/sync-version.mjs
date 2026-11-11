import { readFileSync, writeFileSync } from "node:fs";

// The release job passes the version semantic-release just chose.
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) {
  console.error("usage: sync-version.mjs <major.minor.patch>");
  process.exit(1);
}

const path = new URL("../apps/api/package.json", import.meta.url);
const pkg = JSON.parse(readFileSync(path, "utf8"));
pkg.version = version;
writeFileSync(path, `${JSON.stringify(pkg, null, 2)}\n`);
