import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { NewTenantDialog } from "../components/NewTenantDialog";
import { TopBar } from "../components/TopBar";
import { compactNumber, initials, tenantTint } from "../lib/format";
import { requireAuth, useTenants } from "../lib/queries";

export const Route = createFileRoute("/tenants")({
  beforeLoad: ({ context }) => requireAuth(context.queryClient),
  component: TenantsPage,
});

function TenantsPage() {
  const tenants = useTenants();
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);

  const q = query.trim().toLowerCase();
  const shown = (tenants.data ?? []).filter(
    (t) => !q || t.name.toLowerCase().includes(q) || t.slug.includes(q),
  );

  return (
    <div className="flex min-h-screen flex-col bg-surface text-ink">
      <TopBar title="Tenants" />
      <main className="mx-auto flex w-full max-w-[1120px] flex-1 flex-col gap-7 pt-10 pr-4 pb-16 pl-4 md:pr-6 md:pl-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="flex flex-col gap-1">
            <h1 className="font-display font-semibold text-[30px] tracking-tight">Tenants</h1>
            <p className="text-muted">
              A tenant isolates its own applications, resources and signing keys.
            </p>
          </div>
          <Button onClick={() => setCreating(true)}>
            <span aria-hidden="true">+</span> New tenant
          </Button>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex max-w-[380px] flex-1 basis-70 flex-col">
            <label htmlFor="search" className="sr-only">
              Search tenants
            </label>
            <input
              id="search"
              type="search"
              placeholder="Search tenants…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="h-11 rounded-[10px] border border-line bg-white pr-3 pl-3 text-sm placeholder:text-faint focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent"
            />
          </div>
          <span className="text-[13px] text-muted">{shown.length} tenants</span>
        </div>

        {tenants.isError ? (
          <EmptyState title="Couldn't load tenants" description={tenants.error.message} />
        ) : (
          <ul className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {shown.map((t) => {
              const tint = tenantTint(t.slug);
              return (
                <li key={t.id} className="min-w-0">
                  <Link
                    to="/t/$tenantId/applications"
                    params={{ tenantId: t.id }}
                    className="flex h-full flex-col gap-[18px] rounded-[14px] border border-line bg-white p-5 text-ink hover:border-line-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-3">
                        <div
                          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[10px] font-display font-semibold text-[15px]"
                          style={{ background: tint.tint, color: tint.ink }}
                        >
                          {initials(t.name)}
                        </div>
                        <div className="flex min-w-0 flex-col">
                          <span className="truncate font-semibold text-[15px]">{t.name}</span>
                          <span className="font-mono text-muted text-xs">{t.slug}</span>
                        </div>
                      </div>
                      <Badge tone={t.status === "active" ? "success" : "neutral"}>
                        {t.status === "active" ? "Active" : "Paused"}
                      </Badge>
                    </div>
                    <dl className="grid grid-cols-3 gap-3 border-hover border-t pt-3.5">
                      <Stat label="Apps" value={String(t.appCount)} />
                      <Stat label="Resources" value={String(t.resourceCount)} />
                      <Stat label="Tokens / 24h" value={compactNumber(t.tokens24h)} />
                    </dl>
                  </Link>
                </li>
              );
            })}
            <li className="min-w-0">
              <button
                type="button"
                onClick={() => setCreating(true)}
                className="flex h-full min-h-40 w-full flex-col items-center justify-center gap-2.5 rounded-[14px] border border-line-strong border-dashed bg-transparent p-5 text-muted text-sm hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              >
                <span aria-hidden="true" className="text-xl leading-none">
                  +
                </span>
                Create a tenant
              </button>
            </li>
          </ul>
        )}
      </main>
      <NewTenantDialog open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <dt className="text-[11px] text-muted uppercase tracking-wide">{label}</dt>
      <dd className="m-0 font-semibold text-base">{value}</dd>
    </div>
  );
}
