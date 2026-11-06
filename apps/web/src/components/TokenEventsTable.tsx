import type { TokenEventDto } from "@handsal/shared";
import { useState } from "react";
import { relativeTime } from "../lib/format";
import { Badge } from "./Badge";
import { Table, Td, Th } from "./Table";

const REASONS: Record<string, string> = {
  invalid_scope: "outside granted scopes",
  invalid_target: "unknown or unauthorized resource",
  client_disabled: "client disabled",
  bad_secret: "wrong secret",
  unknown_client: "unknown client",
  auth_method_mismatch: "wrong auth method",
  tenant_paused: "tenant paused",
  invalid_client: "invalid client",
};
const TONES = { issued: "success", denied: "danger", revoked: "warning" } as const;
const LABELS = { issued: "Issued", denied: "Denied", revoked: "Revoked" } as const;

function CopyJti({ jti }: { jti: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <code className="font-mono text-[13px]">{jti.slice(0, 12)}</code>
      <button
        type="button"
        aria-label={`Copy token ID ${jti.slice(0, 12)}`}
        className="text-muted text-xs hover:text-ink"
        onClick={async () => {
          await navigator.clipboard.writeText(jti);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

export function TokenEventsTable({
  events,
  appNames,
  agentIds,
}: {
  events: TokenEventDto[];
  appNames: Map<string, string>;
  agentIds: Set<string>;
}) {
  return (
    <Table minWidth={1000}>
      <thead>
        <tr>
          <Th>Time</Th>
          <Th>Outcome</Th>
          <Th>Client</Th>
          <Th>Agent</Th>
          <Th>Audience</Th>
          <Th>Scopes</Th>
          <Th>Token ID</Th>
          <Th className="text-right">Expires</Th>
        </tr>
      </thead>
      <tbody>
        {events.map((e) => {
          const name = e.applicationId ? appNames.get(e.applicationId) : undefined;
          return (
            <tr key={e.id}>
              <Td className="whitespace-nowrap font-mono text-[13px] text-muted">
                {new Date(e.createdAt).toLocaleTimeString("en-GB", { hour12: false })}
              </Td>
              <Td>
                <Badge tone={TONES[e.outcome]}>{LABELS[e.outcome]}</Badge>
              </Td>
              <Td>
                {name ? (
                  <span className="font-medium">{name}</span>
                ) : (
                  <code className="font-mono text-[13px]">{e.applicationClientId ?? "—"}</code>
                )}
              </Td>
              <Td className="whitespace-nowrap text-body text-sm">
                {e.applicationId && agentIds.has(e.applicationId)
                  ? e.actorSub
                    ? `agent · for ${e.actorSub}`
                    : "agent"
                  : null}
              </Td>
              <Td className="text-body">{e.audience?.replace(/^https?:\/\//, "") ?? "—"}</Td>
              <Td>
                <span className="flex flex-wrap gap-1">
                  {e.scopes.slice(0, 2).map((s) => (
                    <code
                      key={s}
                      className="rounded bg-hover pt-0.5 pr-1.5 pb-0.5 pl-1.5 font-mono text-xs"
                    >
                      {s}
                    </code>
                  ))}
                  {e.scopes.length > 2 && (
                    <span className="text-muted text-xs">+{e.scopes.length - 2}</span>
                  )}
                </span>
              </Td>
              <Td>{e.jti ? <CopyJti jti={e.jti} /> : "—"}</Td>
              <Td className="whitespace-nowrap text-right text-muted text-sm">
                {e.outcome === "denied"
                  ? e.reason
                    ? (REASONS[e.reason] ?? e.reason)
                    : "—"
                  : e.expiresAt
                    ? relativeTime(e.expiresAt)
                    : "—"}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}
