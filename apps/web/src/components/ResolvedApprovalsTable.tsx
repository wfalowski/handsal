import type { ApprovalDto } from "@handsal/shared";
import { relativeTime } from "../lib/format";
import { Badge } from "./Badge";
import { Table, Td, Th } from "./Table";

function decision(a: ApprovalDto) {
  if (a.status === "approved")
    return {
      label: a.decidedBy?.kind === "rule" ? "Auto-approved" : "Approved",
      tone: "success",
    } as const;
  if (a.status === "denied") return { label: "Denied", tone: "danger" } as const;
  return { label: "Expired", tone: "neutral" } as const;
}

function decidedBy(a: ApprovalDto) {
  if (!a.decidedBy) return "—";
  const { kind, label } = a.decidedBy;
  return kind === "rule" ? `rule: ${label}` : kind === "api-key" ? `API key: ${label}` : label;
}

// The DTO has no consumed_at, so the "consumed" column from the brief is not rendered.
export function ResolvedApprovalsTable({ approvals }: { approvals: ApprovalDto[] }) {
  return (
    <Table minWidth={860}>
      <thead>
        <tr>
          <Th>Time</Th>
          <Th>Decision</Th>
          <Th>Agent</Th>
          <Th>Scope</Th>
          <Th>On behalf of</Th>
          <Th className="text-right">Decided by</Th>
        </tr>
      </thead>
      <tbody>
        {approvals.map((a) => {
          const d = decision(a);
          return (
            <tr key={a.id}>
              <Td className="whitespace-nowrap text-muted text-sm">
                {relativeTime(a.decidedAt ?? a.expiresAt)}
              </Td>
              <Td>
                <Badge tone={d.tone}>{d.label}</Badge>
              </Td>
              <Td className="font-medium">{a.applicationName}</Td>
              <Td>
                <span className="flex flex-wrap gap-1">
                  {a.scopes.map((s) => (
                    <code key={s} className="rounded bg-hover px-1.5 py-0.5 font-mono text-xs">
                      {s}
                    </code>
                  ))}
                </span>
              </Td>
              <Td className="text-body text-sm">{a.actorHint ?? "—"}</Td>
              <Td className="whitespace-nowrap text-right text-body text-sm">{decidedBy(a)}</Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
