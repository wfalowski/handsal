/** Turn relative guide links into site paths. The markdown stays valid on GitHub. */
const guides: Record<string, string> = {
  "overview.md": "/docs",
  "overview.pl.md": "/pl/docs",
  "sdk.md": "/docs/sdk",
  "sdk.pl.md": "/pl/docs/sdk",
  "integration.md": "/docs/integration",
  "deployment.md": "/docs/deployment",
  "api.md": "/docs/api",
};

export function rewriteDocLinks(html: string): string {
  const origin = (process.env.SITE_GITHUB_URL ?? "https://github.com/wfalowski/handsal").replace(
    /\/$/,
    "",
  );
  return html.replace(/href="([^"]+)"/g, (full, url: string) => {
    if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith("/") || url.startsWith("#")) return full;
    const hashAt = url.indexOf("#");
    const path = hashAt === -1 ? url : url.slice(0, hashAt);
    const hash = hashAt === -1 ? "" : url.slice(hashAt);
    const file = path.split("/").pop() ?? "";
    const page = guides[file];
    if (page && (path === file || path.endsWith(`/${file}`))) return `href="${page}${hash}"`;
    if (file === "README.md") return `href="${origin}/blob/main/README.md${hash}"`;
    return full;
  });
}
