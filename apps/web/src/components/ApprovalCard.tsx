import type { ApprovalDto } from "@handsal/shared";
import { Link } from "@tanstack/react-router";
import { relativeTime } from "../lib/format";
import { Button } from "./Button";

type Props = {
  tenantId: string;
  approval: ApprovalDto;
  canDecide: boolean;
  onApprove: () => void;
  onDeny: () => void;
  busy: boolean;
};

export function ApprovalCard({ tenantId, approval: a, canDecide, onApprove, onDeny, busy }: Props) {
  return (
    <article className="flex flex-col gap-3.5 rounded-[14px] border border-line bg-white p-5">
      <div className="flex flex-wrap items-center gap-2">
        <Link
          to="/t/$tenantId/applications/$appId"
          params={{ tenantId, appId: a.applicationId }}
          className="font-semibold text-accent hover:underline"
        >
          {a.applicationName}
        </Link>
        <code className="font-mono text-muted text-xs">{a.clientId}</code>
        <span className="text-muted">wants</span>
        {a.scopes.map((s) => (
          <code
            key={s}
            className="rounded-md bg-[#FEF3C7] px-2 py-[3px] font-mono text-[#92400E] text-[12.5px]"
          >
            {s}
          </code>
        ))}
        <span className="text-muted">on</span>
        <code className="font-mono text-[13px]">{a.audience}</code>
      </div>
      {a.justification && (
        <div className="flex flex-col gap-1 rounded-[10px] bg-surface p-3">
          <span className="text-[11px] text-muted uppercase tracking-wide">
            Agent's justification
          </span>
          <p className="text-body text-sm">{a.justification}</p>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[13px] text-muted">
        {a.actorHint && <span>On behalf of {a.actorHint}</span>}
        {a.taskId && (
          <span>
            Task <code className="font-mono">{a.taskId}</code>
          </span>
        )}
        <span>Requested {relativeTime(a.createdAt)}</span>
        <span>Expires {relativeTime(a.expiresAt)}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {canDecide && (
          <>
            <Button size="lg" disabled={busy} onClick={onApprove}>
              Approve once
            </Button>
            <Button size="lg" variant="secondary" disabled={busy} onClick={onDeny}>
              Deny
            </Button>
          </>
        )}
        <Link
          to="/t/$tenantId/tokens"
          params={{ tenantId }}
          search={{ applicationId: a.applicationId, taskId: a.taskId ?? undefined }}
          className="ml-auto inline-flex min-h-11 items-center text-accent text-sm hover:underline"
        >
          Inspect run
        </Link>
      </div>
    </article>
  );
}
