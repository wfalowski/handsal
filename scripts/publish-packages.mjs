import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Publishes @handsal/sdk only. @handsal/shared and @handsal/db stay private.
// The monorepo keeps TypeScript source in "exports" so dev and tests keep
// working. npm gets a staged package whose entry point is the compiled dist.
//
// Runs from the release job after semantic-release. Auth is npm Trusted
// Publishing: the job's GitHub OIDC token, never a registry token. A retry
// publishes only a version that is not on the registry yet. Direct
// `npm publish` inside the package is refused by its prepublishOnly script.
//
// npm can attach a trusted publisher only after the package exists. The first
// version is published once from a laptop with `node scripts/publish-packages.mjs --local`.

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dryRun = process.argv.includes("--dry-run");
const local = process.argv.includes("--local");

const packages = [
  {
    dir: "packages/sdk",
    exports: {
      ".": entry("."),
    },
  },
];

function entry(subpath) {
  const base = subpath === "." ? "./dist/index" : `./dist/${subpath.slice(2)}/index`;
  return {
    types: `${base}.d.ts`,
    import: `${base}.js`,
    default: `${base}.js`,
  };
}

function git(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

function readPackage(dir) {
  return JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
}

function tagsAtHead() {
  const out = git(["tag", "--points-at", "HEAD"]);
  return out
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /^v\d+\.\d+\.\d+$/.test(line));
}

function npmAtLeast(actual, minimum) {
  const parse = (value) => value.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const left = parse(actual);
  const right = parse(minimum);
  for (let i = 0; i < 3; i++) {
    if ((left[i] ?? 0) > (right[i] ?? 0)) return true;
    if ((left[i] ?? 0) < (right[i] ?? 0)) return false;
  }
  return true;
}

function assertNoRegistryToken() {
  if (process.env.NPM_TOKEN || process.env.NODE_AUTH_TOKEN) {
    throw new Error(
      "Unset NPM_TOKEN and NODE_AUTH_TOKEN. Trusted Publishing uses this job's GitHub OIDC token. A registry token makes npm skip OIDC.",
    );
  }
}

function assertTrustedPublishing() {
  assertNoRegistryToken();
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || !process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    throw new Error(
      "GitHub Actions OIDC is not available. Publish runs in .github/workflows/docker.yml with permissions.id-token: write. On npm, add a trusted publisher for @handsal/sdk: repository wfalowski/handsal, workflow filename docker.yml, environment empty, and allow direct npm publish.",
    );
  }
  const version = execFileSync("npm", ["--version"], { cwd: root, encoding: "utf8" }).trim();
  if (!npmAtLeast(version, "11.5.1")) {
    throw new Error(`npm ${version} cannot use Trusted Publishing. Install npm >= 11.5.1.`);
  }
}

function publishedVersion(name, version) {
  try {
    const found = execFileSync("npm", ["view", `${name}@${version}`, "version"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    return found === version;
  } catch {
    return false;
  }
}

function packedFiles(stage) {
  const raw = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: stage,
    encoding: "utf8",
  });
  const packed = JSON.parse(raw);
  return packed[0].files.map((file) => file.path);
}

function assertPacked(name, files) {
  const banned = files.filter(
    (file) =>
      file === "src" ||
      file.startsWith("src/") ||
      file.includes(".test.") ||
      (file.endsWith(".ts") && !file.endsWith(".d.ts")) ||
      file.includes("node_modules/"),
  );
  if (!files.includes("dist/index.js") || !files.includes("dist/index.d.ts")) {
    throw new Error(`${name} tarball is missing dist/index.js or dist/index.d.ts`);
  }
  if (banned.length > 0) {
    throw new Error(`${name} tarball includes files that must not be published: ${banned.join(", ")}`);
  }
}

async function stagePackage(pkg, manifest) {
  const stage = join(root, pkg.dir, ".npm-publish");
  await rm(stage, { recursive: true, force: true });
  await mkdir(stage, { recursive: true });
  await cp(join(root, pkg.dir, "dist"), join(stage, "dist"), {
    recursive: true,
    filter(source) {
      const name = basename(source);
      return !name.includes(".test.") && !name.endsWith(".map");
    },
  });
  await cp(join(root, "LICENSE"), join(stage, "LICENSE"));
  const readme = join(root, pkg.dir, "README.md");
  await cp(readme, join(stage, "README.md"));

  const published = {
    name: manifest.name,
    version: manifest.version,
    description: manifest.description,
    license: manifest.license,
    type: "module",
    engines: manifest.engines,
    repository: manifest.repository,
    homepage: manifest.homepage,
    bugs: manifest.bugs,
    keywords: manifest.keywords,
    sideEffects: manifest.sideEffects,
    files: ["dist"],
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    exports: pkg.exports,
    publishConfig: { access: "public" },
    dependencies: manifest.dependencies,
  };
  if (published.sideEffects === undefined) delete published.sideEffects;
  await writeFile(join(stage, "package.json"), `${JSON.stringify(published, null, 2)}\n`);
  return stage;
}

async function main() {
  const manifests = packages.map((pkg) => ({ pkg, manifest: readPackage(pkg.dir) }));
  for (const { pkg, manifest } of manifests) {
    if (manifest.name !== "@handsal/sdk") {
      throw new Error(`${pkg.dir} must be named @handsal/sdk (got ${manifest.name})`);
    }
    if (manifest.private === true) {
      throw new Error(`${manifest.name} is private`);
    }
    for (const range of Object.values(manifest.dependencies ?? {})) {
      if (String(range).startsWith("workspace:")) {
        throw new Error(`${manifest.name} depends on ${range}; npm cannot install a workspace spec`);
      }
    }
  }

  const version = manifests[0].manifest.version;

  if (local) {
    assertNoRegistryToken();
    console.log(`Local publish of ${manifests[0].manifest.name}@${version} with the current npm login.`);
  } else if (!dryRun) {
    const tags = tagsAtHead();
    if (!tags.includes(`v${version}`)) {
      console.log(`HEAD is not tagged v${version}. Skip npm publish.`);
      return;
    }
    assertTrustedPublishing();
  }

  execFileSync("pnpm", ["--filter", "./packages/sdk", "build"], { cwd: root, stdio: "inherit" });

  for (const { pkg, manifest } of manifests) {
    const stage = await stagePackage(pkg, manifest);
    try {
      const files = packedFiles(stage);
      assertPacked(manifest.name, files);
      if (dryRun) {
        const published = JSON.parse(readFileSync(join(stage, "package.json"), "utf8"));
        console.log(`\n${published.name}@${published.version}`);
        console.log(JSON.stringify({ exports: published.exports, dependencies: published.dependencies }, null, 2));
        for (const file of files) console.log(`  ${file}`);
        continue;
      }
      if (publishedVersion(manifest.name, manifest.version)) {
        console.log(`${manifest.name}@${manifest.version} is already on npm. Skip.`);
        continue;
      }
      const args = ["publish", "--access", "public", "--ignore-scripts"];
      if (!local) args.push("--provenance");
      execFileSync("npm", args, { cwd: stage, stdio: "inherit" });
      console.log(`Published ${manifest.name}@${manifest.version}`);
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
