import clsx from "clsx";
import { useState } from "react";
import type { GrantView, ResourceWithScopes } from "../lib/queries";
import { useGrantsSave } from "../lib/queries";
import { Button } from "./Button";
import { useToast } from "./Toast";

type Props = {
  tenantId: string;
  appId: string;
  resources: ResourceWithScopes[];
  grants: GrantView[];
  canEdit: boolean;
};

const key = (ids: Iterable<string>) => [...ids].sort().join(",");

export function GrantsMatrix({ tenantId, appId, resources, grants, canEdit }: Props) {
  const toast = useToast();
  const save = useGrantsSave(tenantId, appId);
  const serverIds = grants.flatMap((g) => g.scopes.map((s) => s.id));
  const serverKey = key(serverIds);
  // Local edits are a draft on top of the server state; null = no edits.
  const [draft, setDraft] = useState<Set<string> | null>(null);
  const selected = draft ?? new Set(serverIds);
  const dirty = draft !== null && key(draft) !== serverKey;

  function toggle(id: string) {
    const next = new Set(selected);
    if (!next.delete(id)) next.add(id);
    setDraft(next);
  }

  const total = resources.reduce(
    (n, r) => n + r.scopes.filter((s) => selected.has(s.id)).length,
    0,
  );
  const withGrants = resources.filter((r) => r.scopes.some((s) => selected.has(s.id))).length;

  return (
    <section className="flex flex-col rounded-[14px] border border-line bg-white">
      <div className="border-hover border-b pt-[18px] pr-5 pb-[18px] pl-5">
        <h2 className="font-semibold text-[15px]">Access</h2>
        <span className="text-muted text-[13px]">
          {total} scopes granted across {withGrants} resources
        </span>
      </div>
      {resources.length === 0 && (
        <p className="p-5 text-muted">No resources yet. Create a resource to grant access.</p>
      )}
      {resources.map((r) => {
        const granted = r.scopes.filter((s) => selected.has(s.id)).length;
        return (
          <div key={r.id} className="flex flex-col gap-3 border-hover border-b p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex min-w-0 flex-col leading-snug">
                <span className="font-semibold">{r.name}</span>
                <span className="truncate font-mono text-muted text-xs">{r.audience}</span>
              </div>
              <span className="text-muted text-xs">
                {granted} / {r.scopes.length} scopes
              </span>
            </div>
            {r.scopes.length === 0 ? (
              <span className="text-muted text-xs">This resource has no scopes.</span>
            ) : (
              <div className="flex flex-wrap gap-2">
                {r.scopes.map((s) => {
                  const on = selected.has(s.id);
                  return (
                    <label
                      key={s.id}
                      className={clsx(
                        "inline-flex h-8 items-center gap-2 rounded-lg border pr-3 pl-2.5 font-mono text-[12.5px]",
                        canEdit ? "cursor-pointer" : "cursor-not-allowed opacity-70",
                        on ? "border-accent bg-[#F5F7FF] text-ink" : "border-line text-body",
                        "has-[:focus-visible]:outline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-accent",
                      )}
                    >
                      <input
                        type="checkbox"
                        className="accent-accent"
                        checked={on}
                        disabled={!canEdit}
                        onChange={() => toggle(s.id)}
                      />
                      {s.name}
                    </label>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
      {canEdit && (
        <div className="flex justify-end gap-2 p-3.5 pr-5">
          <Button variant="secondary" size="sm" disabled={!dirty} onClick={() => setDraft(null)}>
            Discard
          </Button>
          <Button
            size="sm"
            disabled={!dirty}
            loading={save.isPending}
            onClick={() =>
              save.mutate([...selected], {
                onSuccess: () => {
                  setDraft(null);
                  toast.success("Access updated");
                },
                onError: (err) => toast.error(err.message),
              })
            }
          >
            Save changes
          </Button>
        </div>
      )}
    </section>
  );
}
