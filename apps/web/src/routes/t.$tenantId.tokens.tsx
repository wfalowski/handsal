import { createFileRoute, useNavigate } from "@tanstack/react-router";
import clsx from "clsx";
import { useEffect, useState } from "react";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { RecentTasks } from "../components/RecentTasks";
import { StatTile } from "../components/StatTile";
import { TokenEventsTable } from "../components/TokenEventsTable";
import { useAgentAppIds, useTokenApps, useTokenEvents, useTokenStats } from "../lib/queries";

const FILTERS = [
  { id: "all", label: "All" },
  { id: "issued", label: "Issued" },
  { id: "attention", label: "Needs attention" },
] as const;
type Filter = (typeof FILTERS)[number]["id"];

export const Route = createFileRoute("/t/$tenantId/tokens")({
  validateSearch: (
    s: Record<string, unknown>,
  ): {
    applicationId?: string;
    taskId?: string;
    filter?: Filter;
  } => ({
    applicationId: typeof s.applicationId === "string" ? s.applicationId : undefined,
    taskId: typeof s.taskId === "string" && s.taskId ? s.taskId.slice(0, 128) : undefined,
    filter: FILTERS.some((f) => f.id === s.filter) ? (s.filter as Filter) : undefined,
  }),
  component: TokensPage,
});

function TokensPage() {
  const { tenantId } = Route.useParams();
  const { applicationId, taskId, filter = "all" } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });

  const [input, setInput] = useState("");
  const [q, setQ] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setQ(input.trim()), 250);
    return () => clearTimeout(t);
  }, [input]);

  const common = { applicationId, taskId, q: q || undefined };
  // The API takes a single `outcome`, so "Needs attention" = denied + revoked: two queries merged
  // by createdAt desc. shortcut: each stream paginates independently, fine for an activity feed.
  const attention = filter === "attention";
  const main = useTokenEvents(tenantId, {
    ...common,
    outcome: filter === "issued" ? "issued" : attention ? "denied" : undefined,
  });
  const revoked = useTokenEvents(tenantId, { ...common, outcome: "revoked", enabled: attention });
  const stats = useTokenStats(tenantId);
  const apps = useTokenApps(tenantId);
  const agents = useAgentAppIds(tenantId);

  const queries = attention ? [main, revoked] : [main];
  const events = queries
    .flatMap((r) => r.data?.pages.flatMap((p) => p.items) ?? [])
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const hasNext = queries.some((r) => r.hasNextPage);
  const fetching = queries.some((r) => r.isFetching);
  const loadingMore = queries.some((r) => r.isFetchingNextPage);
  const appNames = apps.data ?? new Map<string, string>();
  const s = stats.data;

  const setSearch = (next: { applicationId?: string; taskId?: string; filter?: Filter }) =>
    navigate({ search: (prev) => ({ ...prev, ...next }), replace: true });

  const delta =
    s && s.issuedPrev24h > 0 ? ((s.issued24h - s.issuedPrev24h) / s.issuedPrev24h) * 100 : null;
  const deniedPct = s && s.requests24h > 0 ? (s.denied24h / s.requests24h) * 100 : 0;

  return (
    <div className="flex flex-col gap-7">
      <div className="flex flex-col gap-1">
        <h1 className="font-display font-semibold text-[30px] tracking-tight">Token activity</h1>
        <p className="text-muted">
          Every token request against this tenant's issuer, last 24 hours.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatTile
          label="Tokens issued"
          value={s ? s.issued24h.toLocaleString("en-US") : "—"}
          sub={
            delta === null
              ? "— vs previous 24h"
              : `${delta >= 0 ? "+" : ""}${delta.toFixed(1)}% vs previous 24h`
          }
          subTone={delta !== null && delta >= 0 ? "success" : "muted"}
        />
        <StatTile
          label="Denied requests"
          value={s ? s.denied24h.toLocaleString("en-US") : "—"}
          sub={`${deniedPct.toFixed(2)}% of requests`}
        />
        <StatTile
          label="Active clients"
          value={
            s ? (
              <>
                {s.activeApps24h}{" "}
                <span className="font-medium font-sans text-muted text-sm">/ {s.totalApps}</span>
              </>
            ) : (
              "—"
            )
          }
          sub="made a request in the last 24 h"
        />
      </div>

      <RecentTasks
        tenantId={tenantId}
        selected={taskId}
        onSelect={(id) => setSearch({ taskId: id })}
      />

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-[360px] flex-1 basis-[260px]">
          <label htmlFor="token-q" className="sr-only">
            Search by client or token ID
          </label>
          <input
            id="token-q"
            type="search"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Client ID or token ID…"
            className="h-10 w-full rounded-[10px] border border-line bg-white pr-3 pl-3 text-sm placeholder:text-faint focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent"
          />
        </div>
        <fieldset
          aria-label="Filter by outcome"
          className="m-0 inline-flex min-w-0 gap-0.5 rounded-[10px] border border-line bg-white p-[3px]"
        >
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              aria-pressed={filter === f.id}
              onClick={() => setSearch({ filter: f.id === "all" ? undefined : f.id })}
              className={clsx(
                "h-8 rounded-[7px] pr-3 pl-3 font-medium text-[13px]",
                filter === f.id ? "bg-ink text-white" : "text-body hover:bg-hover",
              )}
            >
              {f.label}
            </button>
          ))}
        </fieldset>
        {applicationId && (
          <button
            type="button"
            onClick={() => setSearch({ applicationId: undefined })}
            aria-label="Remove client filter"
            className="inline-flex h-8 items-center gap-2 rounded-full bg-hover pr-3 pl-3 text-[13px]"
          >
            Client: {appNames.get(applicationId) ?? applicationId.slice(0, 8)}
            <span aria-hidden="true">×</span>
          </button>
        )}
        {taskId && (
          <button
            type="button"
            onClick={() => setSearch({ taskId: undefined })}
            aria-label="Remove task filter"
            className="inline-flex h-8 items-center gap-2 rounded-full bg-hover pr-3 pl-3 text-[13px]"
          >
            Task: <code className="font-mono">{taskId}</code>
            <span aria-hidden="true">×</span>
          </button>
        )}
        <span className="ml-auto inline-flex items-center gap-2 text-[13px] text-muted">
          <span
            aria-hidden="true"
            className={clsx("size-2 rounded-full bg-success", fetching && "animate-pulse")}
          />
          Live · updates every 5 s
        </span>
      </div>

      {main.isPending ? (
        <p className="text-muted">Loading…</p>
      ) : main.isError ? (
        <EmptyState title="Couldn't load token activity" description={main.error.message} />
      ) : events.length === 0 ? (
        <EmptyState
          title="No token activity"
          description="No token requests match these filters yet."
        />
      ) : (
        <>
          <TokenEventsTable
            events={events}
            appNames={appNames}
            agentIds={agents.data ?? new Set<string>()}
          />
          {hasNext && (
            <div className="flex justify-center">
              <Button
                variant="secondary"
                loading={loadingMore}
                onClick={() => {
                  for (const r of queries) if (r.hasNextPage) r.fetchNextPage();
                }}
              >
                Load more
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
