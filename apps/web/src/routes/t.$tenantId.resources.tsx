import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { Button } from "../components/Button";
import { EmptyState } from "../components/EmptyState";
import { ResourceDetail } from "../components/ResourceDetail";
import { ResourceForm } from "../components/ResourceForm";
import { ResourceList } from "../components/ResourceList";
import { useResource, useResources } from "../lib/queries";

export const Route = createFileRoute("/t/$tenantId/resources")({
  validateSearch: (s: Record<string, unknown>): { resource?: string } =>
    typeof s.resource === "string" && s.resource ? { resource: s.resource } : {},
  component: ResourcesPage,
});

function ResourcesPage() {
  const { tenantId } = Route.useParams();
  const { resource } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const [creating, setCreating] = useState(false);
  const list = useResources(tenantId);
  // Fall back to the first resource when the URL has none (or a stale/deleted id).
  const selected = list.data?.find((r) => r.id === resource) ?? list.data?.[0];
  const detail = useResource(tenantId, selected?.id);

  const select = (id: string | undefined) =>
    navigate({ search: id ? { resource: id } : {}, replace: true });

  return (
    <div className="flex flex-col gap-7 p-6 md:p-10">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <h1 className="font-display font-semibold text-3xl tracking-tight">Resources</h1>
          <p className="text-muted">
            A resource is an API or MCP server your services protect. Its scopes are the permissions
            applications and agents can be granted.
          </p>
        </div>
        <Button onClick={() => setCreating(true)}>New resource</Button>
      </div>

      {list.isPending ? null : list.isError ? (
        <EmptyState title="Couldn't load resources" description={list.error.message} />
      ) : list.data.length === 0 ? (
        <EmptyState
          title="No resources yet"
          description="Register the API or MCP server your tokens are issued for."
          action={<Button onClick={() => setCreating(true)}>New resource</Button>}
        />
      ) : (
        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
          <ResourceList resources={list.data} selectedId={selected?.id} onSelect={select} />
          {detail.data && selected && (
            <ResourceDetail
              key={detail.data.id}
              tenantId={tenantId}
              resource={detail.data}
              tokens24h={selected.tokens24h}
              onDeleted={() => select(undefined)}
            />
          )}
        </div>
      )}

      <ResourceForm
        open={creating}
        onClose={() => setCreating(false)}
        tenantId={tenantId}
        onSaved={select}
      />
    </div>
  );
}
