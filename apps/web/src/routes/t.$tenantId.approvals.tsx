import type { ApprovalDto } from "@handsal/shared";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import clsx from "clsx";
import { useState } from "react";
import { ApprovalCard } from "../components/ApprovalCard";
import { Button } from "../components/Button";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { ResolvedApprovalsTable } from "../components/ResolvedApprovalsTable";
import { StatTile } from "../components/StatTile";
import { useToast } from "../components/Toast";
import { relativeTime } from "../lib/format";
import { useApprovals, useDecideApproval, useMe } from "../lib/queries";

const TABS = [
  { id: "pending", label: "Pending" },
  { id: "resolved", label: "Resolved" },
] as const;
type Tab = (typeof TABS)[number]["id"];

export const Route = createFileRoute("/t/$tenantId/approvals")({
  validateSearch: (s: Record<string, unknown>): { tab?: Tab } => ({
    tab: s.tab === "resolved" ? "resolved" : undefined,
  }),
  component: ApprovalsPage,
});

function ApprovalsPage() {
  const { tenantId } = Route.useParams();
  const { tab = "pending" } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const toast = useToast();
  const role = useMe().data?.tenants.find((t) => t.id === tenantId)?.role;
  const canDecide = role === "owner" || role === "admin";

  const list = useApprovals(tenantId, tab);
  const decide = useDecideApproval(tenantId);
  const [denying, setDenying] = useState<ApprovalDto>();

  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const counts = list.data?.pages[0]?.counts;
  const median =
    counts?.medianWaitSeconds != null
      ? Math.max(1, Math.round(counts.medianWaitSeconds / 60))
      : null;

  function run(a: ApprovalDto, action: "approve" | "deny") {
    decide.mutate(
      { id: a.id, action },
      {
        onSuccess: () => {
          toast.success(action === "approve" ? "Approved once" : "Request denied");
          setDenying(undefined);
        },
        onError: (err) => {
          toast.error(err.message);
          setDenying(undefined);
        },
      },
    );
  }

  return (
    <div className="flex flex-col gap-7">
      <div className="flex flex-col gap-1">
        <h1 className="font-display font-semibold text-[30px] tracking-tight">Approvals</h1>
        <p className="text-muted">
          Agents asking for scopes marked "human approval". The token is issued only after someone
          here says yes.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatTile
          label="Waiting now"
          value={<span className="text-accent">{counts?.pending ?? "—"}</span>}
          sub={counts?.oldestPendingAt ? `oldest ${relativeTime(counts.oldestPendingAt)}` : "—"}
        />
        <StatTile
          label="Approved today"
          value={counts?.approvedToday ?? "—"}
          sub={`${counts?.deniedToday ?? 0} denied`}
        />
        <StatTile
          label="Median wait"
          value={
            median === null ? (
              "—"
            ) : (
              <>
                {median} <span className="font-medium font-sans text-muted text-sm">min</span>
              </>
            )
          }
          sub="requests expire after 30 min"
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div
          role="tablist"
          aria-label="Approvals"
          className="inline-flex gap-0.5 rounded-[10px] border border-line bg-white p-[3px]"
        >
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`approvals-tab-${t.id}`}
              aria-controls="approvals-panel"
              aria-selected={tab === t.id}
              onClick={() =>
                navigate({ search: { tab: t.id === "pending" ? undefined : t.id }, replace: true })
              }
              className={clsx(
                "h-11 rounded-[7px] pr-4 pl-4 font-medium text-[13px] md:h-9",
                tab === t.id ? "bg-ink text-white" : "text-body hover:bg-hover",
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
        <p className="text-muted text-[13px]">
          Approving once issues a single 5-minute token. Nothing is granted permanently from here.
        </p>
      </div>

      <div role="tabpanel" id="approvals-panel" aria-labelledby={`approvals-tab-${tab}`}>
        {list.isPending ? (
          <p className="text-muted">Loading…</p>
        ) : list.isError ? (
          <EmptyState title="Couldn't load approvals" description={list.error.message} />
        ) : items.length === 0 ? (
          tab === "pending" ? (
            <EmptyState
              title="Queue is clear"
              description="New requests for marked scopes will appear here."
            />
          ) : (
            <EmptyState
              title="Nothing resolved yet"
              description="Decided requests will appear here."
            />
          )
        ) : (
          <>
            {tab === "pending" ? (
              <div className="flex flex-col gap-4">
                {items.map((a) => (
                  <ApprovalCard
                    key={a.id}
                    tenantId={tenantId}
                    approval={a}
                    canDecide={canDecide}
                    busy={decide.isPending && decide.variables?.id === a.id}
                    onApprove={() => run(a, "approve")}
                    onDeny={() => setDenying(a)}
                  />
                ))}
              </div>
            ) : (
              <ResolvedApprovalsTable approvals={items} />
            )}
            {list.hasNextPage && (
              <div className="flex justify-center">
                <Button
                  variant="secondary"
                  loading={list.isFetchingNextPage}
                  onClick={() => list.fetchNextPage()}
                >
                  Load more
                </Button>
              </div>
            )}
          </>
        )}
      </div>

      <ConfirmDialog
        open={!!denying}
        onClose={() => setDenying(undefined)}
        title="Deny request"
        confirmLabel="Deny"
        danger
        loading={decide.isPending}
        onConfirm={() => denying && run(denying, "deny")}
      >
        <span className="font-medium">{denying?.applicationName}</span> will not receive a token for{" "}
        <span className="font-mono">{denying?.scopes.join(" ")}</span>.
      </ConfirmDialog>
    </div>
  );
}
