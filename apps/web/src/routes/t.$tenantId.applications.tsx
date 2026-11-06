import { createFileRoute, Outlet, useChildMatches, useNavigate } from "@tanstack/react-router";
import clsx from "clsx";
import { useEffect, useState } from "react";
import { ApplicationForm } from "../components/ApplicationForm";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { Table, Td, Th } from "../components/Table";
import { useToast } from "../components/Toast";
import { relativeTime } from "../lib/format";
import {
  type ApplicationListItem,
  type ApplicationStatusFilter,
  useApplicationsList,
  useMe,
} from "../lib/queries";

export const Route = createFileRoute("/t/$tenantId/applications")({
  component: ApplicationsLayout,
});

/** Parent of the detail route: render the child when one matches, otherwise the list. */
function ApplicationsLayout() {
  const hasChild = useChildMatches().length > 0;
  return hasChild ? <Outlet /> : <ApplicationsPage />;
}

const FILTERS: { id: "all" | ApplicationStatusFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "active", label: "Active" },
  { id: "needs_attention", label: "Needs attention" },
];
const MAX_CHIPS = 2;

function statusBadge(app: ApplicationListItem) {
  if (app.status === "disabled") return <Badge>Disabled</Badge>;
  if (app.previousSecretExpiresAt && new Date(app.previousSecretExpiresAt) > new Date()) {
    return <Badge tone="warning">Secret rotating</Badge>;
  }
  return <Badge tone="success">Active</Badge>;
}

function ApplicationsPage() {
  const { tenantId } = Route.useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const role = useMe().data?.tenants.find((t) => t.id === tenantId)?.role;
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"all" | ApplicationStatusFilter>("all");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 250);
    return () => clearTimeout(t);
  }, [search]);

  const apps = useApplicationsList(tenantId, {
    q,
    status: filter === "all" ? undefined : filter,
  });
  const error = apps.error?.message;
  useEffect(() => {
    if (error) toast.error(error);
  }, [error, toast]);

  const items = apps.data ?? [];
  const open = (appId: string) =>
    navigate({ to: "/t/$tenantId/applications/$appId", params: { tenantId, appId } });

  return (
    <div className="flex flex-col gap-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="font-display font-semibold text-3xl tracking-tight">Applications</h1>
          <p className="text-muted">
            Each application is a machine client with its own credentials and granted scopes.
          </p>
        </div>
        {role !== "auditor" && <Button onClick={() => setCreating(true)}>New application</Button>}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 basis-64 md:max-w-sm">
          <label htmlFor="app-search" className="sr-only">
            Search applications
          </label>
          <input
            id="app-search"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or client ID…"
            className="h-10 w-full rounded-[10px] border border-line bg-white pr-3 pl-3 text-ink text-sm placeholder:text-faint focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent"
          />
        </div>
        <fieldset className="m-0 inline-flex min-w-0 gap-0.5 rounded-[10px] border border-line bg-white p-[3px]">
          <legend className="sr-only">Filter by status</legend>
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              aria-pressed={filter === f.id}
              onClick={() => setFilter(f.id)}
              className={clsx(
                "h-8 rounded-[7px] pr-3 pl-3 font-medium text-[13px]",
                filter === f.id ? "bg-hover text-accent" : "text-body",
              )}
            >
              {f.label}
            </button>
          ))}
        </fieldset>
      </div>

      {apps.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : items.length === 0 ? (
        <EmptyState
          title={q || filter !== "all" ? "No matching applications" : "No applications yet"}
          description={
            q || filter !== "all"
              ? "Try a different search or filter."
              : "Create an application to get client credentials for the client_credentials grant."
          }
        />
      ) : (
        <Table minWidth={820}>
          <thead>
            <tr>
              <Th>Application</Th>
              <Th>Client ID</Th>
              <Th>Resources</Th>
              <Th>Scopes</Th>
              <Th>Status</Th>
              <Th>Last token</Th>
              <Th>
                <span className="sr-only">Open</span>
              </Th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id} onClick={() => open(a.id)} className="cursor-pointer hover:bg-surface">
                <Td>
                  <div className="flex flex-col leading-snug">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        open(a.id);
                      }}
                      className="text-left font-semibold text-ink"
                    >
                      {a.name}
                    </button>
                    {a.description && <span className="text-muted text-xs">{a.description}</span>}
                  </div>
                </Td>
                <Td className="whitespace-nowrap font-mono text-body text-xs">{a.clientId}</Td>
                <Td>{a.resourceCount}</Td>
                <Td>
                  <div className="flex flex-wrap gap-1.5">
                    {a.scopeNames.slice(0, MAX_CHIPS).map((s) => (
                      <span
                        key={s}
                        className="whitespace-nowrap rounded-md bg-hover pt-0.5 pr-2 pb-0.5 pl-2 font-mono text-body text-[11.5px]"
                      >
                        {s}
                      </span>
                    ))}
                    {a.scopeNames.length > MAX_CHIPS && (
                      <span className="text-muted text-[11.5px]">
                        +{a.scopeNames.length - MAX_CHIPS}
                      </span>
                    )}
                  </div>
                </Td>
                <Td>{statusBadge(a)}</Td>
                <Td className="whitespace-nowrap text-muted">
                  {a.lastTokenAt ? relativeTime(a.lastTokenAt) : "Never"}
                </Td>
                <Td className="text-right text-muted" aria-hidden="true">
                  ›
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <ApplicationForm tenantId={tenantId} open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}
