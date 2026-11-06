import { useState } from "react";
import { type ResourceDetail, useDeleteScope } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { EmptyState } from "./EmptyState";
import { POLICY_LABELS, ScopeForm } from "./ScopeForm";
import { Table, Td, Th } from "./Table";
import { useToast } from "./Toast";

type Scope = ResourceDetail["scopes"][number];
type Props = { tenantId: string; resourceId: string; scopes: Scope[]; canEdit: boolean };

export function ScopeTable({ tenantId, resourceId, scopes, canEdit }: Props) {
  const toast = useToast();
  const del = useDeleteScope(tenantId, resourceId);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Scope>();
  const [deleting, setDeleting] = useState<Scope>();

  return (
    <div className="flex flex-col gap-3 px-5 pt-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-sm">Scopes</h3>
        {canEdit && (
          <Button variant="secondary" size="sm" onClick={() => setAdding(true)}>
            Add scope
          </Button>
        )}
      </div>
      {scopes.length === 0 ? (
        <EmptyState
          title="No scopes yet"
          description="Scopes are the permissions applications can be granted on this resource."
        />
      ) : (
        <Table minWidth={620}>
          <thead>
            <tr>
              <Th>Scope</Th>
              <Th>Description</Th>
              <Th>Agent policy</Th>
              <Th className="text-right">Granted to</Th>
              {canEdit && (
                <Th>
                  <span className="sr-only">Actions</span>
                </Th>
              )}
            </tr>
          </thead>
          <tbody>
            {scopes.map((s) => (
              <tr key={s.id}>
                <Td className="whitespace-nowrap">
                  <span className="rounded-md bg-hover px-2 py-[3px] font-mono text-[12.5px]">
                    {s.name}
                  </span>
                </Td>
                <Td className="text-body">{s.description ?? "—"}</Td>
                <Td className="whitespace-nowrap text-body">{POLICY_LABELS[s.agentPolicy]}</Td>
                <Td className="whitespace-nowrap text-right text-muted">
                  {s.grantedAppCount} apps
                </Td>
                {canEdit && (
                  <Td className="whitespace-nowrap text-right">
                    <Button variant="ghost" size="sm" onClick={() => setEditing(s)}>
                      Edit
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setDeleting(s)}>
                      Delete
                    </Button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <ScopeForm
        open={adding}
        onClose={() => setAdding(false)}
        tenantId={tenantId}
        resourceId={resourceId}
      />
      <ScopeForm
        open={!!editing}
        onClose={() => setEditing(undefined)}
        tenantId={tenantId}
        resourceId={resourceId}
        scope={editing}
      />
      <Dialog open={!!deleting} onClose={() => setDeleting(undefined)} title="Delete scope">
        <p className="text-body text-sm">
          Delete <span className="font-mono">{deleting?.name}</span>? It is removed from{" "}
          {deleting?.grantedAppCount ?? 0} application grants.
        </p>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setDeleting(undefined)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            loading={del.isPending}
            onClick={() =>
              deleting &&
              del.mutate(deleting.id, {
                onSuccess: () => {
                  toast.success("Scope deleted");
                  setDeleting(undefined);
                },
                onError: (err) => toast.error(err.message),
              })
            }
          >
            Delete scope
          </Button>
        </div>
      </Dialog>
    </div>
  );
}
