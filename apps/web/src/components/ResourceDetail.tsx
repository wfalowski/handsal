import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { type ResourceDetail as Detail, useDeleteResource } from "../lib/queries";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { ResourceForm } from "./ResourceForm";
import { ScopeTable } from "./ScopeTable";
import { useToast } from "./Toast";

type Props = { tenantId: string; resource: Detail; tokens24h?: number; onDeleted: () => void };

const TTL_LABELS: Record<number, string> = {
  900: "15 min",
  3600: "1 h",
  28800: "8 h",
  86400: "24 h",
};

export function ResourceDetail({ tenantId, resource, tokens24h, onDeleted }: Props) {
  const toast = useToast();
  const del = useDeleteResource(tenantId);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirm, setConfirm] = useState("");
  const ttl = resource.tokenTtlSeconds;

  const facts: [string, string][] = [
    ["Token lifetime", ttl == null ? "inherits tenant default" : (TTL_LABELS[ttl] ?? `${ttl} s`)],
    ["Signing", "ES256"],
    ["Tokens / 24h", tokens24h == null ? "—" : String(tokens24h)],
  ];

  return (
    <section className="flex min-w-0 flex-col rounded-[14px] border border-line bg-white pb-5">
      <div className="flex flex-wrap items-start justify-between gap-3 border-hover border-b p-5">
        <div className="flex min-w-0 flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="font-display font-semibold text-xl tracking-tight">{resource.name}</h2>
            <Badge tone={resource.kind === "mcp" ? "info" : "neutral"}>
              {resource.kind === "mcp" ? "MCP server" : "API"}
            </Badge>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted text-xs">Audience</span>
            <code className="break-all rounded-md border border-line bg-surface px-2 py-0.5 font-mono text-[12.5px]">
              {resource.audience}
            </code>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
            Edit
          </Button>
          <Button
            variant="secondary"
            size="sm"
            className="border-red-200 text-danger"
            onClick={() => {
              setConfirm("");
              setDeleting(true);
            }}
          >
            Delete
          </Button>
        </div>
      </div>

      <dl className="grid grid-cols-3 border-hover border-b">
        {facts.map(([k, v], i) => (
          <div
            key={k}
            className={`flex flex-col px-5 py-3.5 ${i < 2 ? "border-hover border-r" : ""}`}
          >
            <dt className="text-[11px] text-muted uppercase tracking-wide">{k}</dt>
            <dd className="font-semibold text-[15px]">{v}</dd>
          </div>
        ))}
      </dl>

      <ScopeTable tenantId={tenantId} resourceId={resource.id} scopes={resource.scopes} />

      <div className="flex flex-col gap-2.5 px-5 pt-5">
        <h3 className="font-semibold text-sm">Applications with access</h3>
        {resource.applications.length === 0 ? (
          <p className="text-muted text-sm">No application has been granted a scope yet.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {resource.applications.map((a) => (
              <Link
                key={a.id}
                // The app-detail route lands with Task 4.2; the casts keep this compiling before it does.
                to={"/t/$tenantId/applications/$appId" as "/t/$tenantId/applications"}
                params={{ tenantId, appId: a.id } as { tenantId: string }}
                className="inline-flex h-8 items-center rounded-lg border border-line px-3 font-medium text-[13px] hover:bg-surface"
              >
                {a.name}
              </Link>
            ))}
          </div>
        )}
      </div>

      <ResourceForm
        open={editing}
        onClose={() => setEditing(false)}
        tenantId={tenantId}
        resource={resource}
      />
      <Dialog open={deleting} onClose={() => setDeleting(false)} title="Delete resource">
        <p className="text-body text-sm">
          This also deletes its {resource.scopes.length} scopes and every grant of them to
          applications. Tokens already issued stay valid until they expire.
        </p>
        <Input
          label={`Type ${resource.name} to confirm`}
          value={confirm}
          autoComplete="off"
          onChange={(e) => setConfirm(e.target.value)}
        />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setDeleting(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            loading={del.isPending}
            disabled={confirm !== resource.name}
            onClick={() =>
              del.mutate(resource.id, {
                onSuccess: () => {
                  toast.success(`Resource ${resource.name} deleted`);
                  setDeleting(false);
                  onDeleted();
                },
                onError: (err) => toast.error(err.message),
              })
            }
          >
            Delete resource
          </Button>
        </div>
      </Dialog>
    </section>
  );
}
