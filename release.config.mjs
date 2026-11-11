/** Conventional Commits on main → semver tag, changelog, GitHub release. No npm publish. */
export default {
  branches: ["main"],
  tagFormat: "v${version}",
  plugins: [
    // Preset 9.3.1 (package.json). v10 needs conventional-changelog-writer 9;
    // semantic-release 25 still ships writer 8, and v10's notes template fails on it.
    ["@semantic-release/commit-analyzer", { preset: "conventionalcommits" }],
    ["@semantic-release/release-notes-generator", { preset: "conventionalcommits" }],
    ["@semantic-release/changelog", { changelogFile: "CHANGELOG.md" }],
    ["@semantic-release/npm", { npmPublish: false }],
    [
      "@semantic-release/exec",
      {
        // npm only rewrites the root manifest. /health reads apps/api/package.json.
        prepareCmd:
          "node scripts/sync-version.mjs ${nextRelease.version} && pnpm exec biome check --write package.json apps/api/package.json",
      },
    ],
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md", "package.json", "apps/api/package.json"],
        message: "chore(release): ${nextRelease.version}\n\n${nextRelease.notes}",
      },
    ],
    "@semantic-release/github",
  ],
};
