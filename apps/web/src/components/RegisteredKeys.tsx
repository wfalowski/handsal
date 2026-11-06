import type { ApplicationKeyDto } from "@handsal/shared";
import { useState } from "react";
import {
  useApplicationKeys,
  useDeleteApplicationKey,
  useRetireApplicationKey,
} from "../lib/queries";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { EmptyState } from "./EmptyState";
import { useToast } from "./Toast";

/** Colon-grouped hex, elided in the middle: a3:9f:12:7e:…:c4. */
function shortFingerprint(fp: string) {
  const pairs = fp.includes(":") ? fp.split(":") : (fp.match(/.{1,2}/g) ?? []);
  return pairs.length > 5
    ? `${pairs.slice(0, 4).join(":")}:…:${pairs[pairs.length - 1]}`
    : pairs.join(":");
}

const fmt = (iso: string) =>
  new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });

type Target = { key: ApplicationKeyDto; action: "retire" | "delete" };
type Props = { tenantId: string; appId: string; canEdit: boolean };

export function RegisteredKeys({ tenantId, appId, canEdit }: Props) {
  const toast = useToast();
  const keys = useApplicationKeys(tenantId, appId);
  const retire = useRetireApplicationKey(tenantId, appId);
  const del = useDeleteApplicationKey(tenantId, appId);
  const [target, setTarget] = useState<Target | null>(null);

  function confirm() {
    if (!target) return;
    const m = target.action === "retire" ? retire : del;
    m.mutate(target.key.id, {
      onSuccess: () => toast.success(target.action === "retire" ? "Key retired" : "Key deleted"),
      onError: (err) => toast.error(err.message),
      onSettled: () => setTarget(null),
    });
  }

  return (
    <section aria-labelledby="registered-keys" className="flex flex-col gap-2.5">
      <h3 id="registered-keys" className="font-medium text-[13px] text-body">
        Registered public keys
      </h3>
      {keys.isPending ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : keys.isError ? (
        <p className="text-danger text-sm">Could not load keys: {keys.error.message}</p>
      ) : keys.data.length === 0 ? (
        <EmptyState
          title="No public keys registered"
          description="Register a public key so the runtime can authenticate with private_key_jwt."
        />
      ) : (
        <ul className="m-0 flex list-none flex-col rounded-[10px] border border-line p-0">
          {keys.data.map((k) => (
            <li
              key={k.id}
              className="flex flex-wrap items-center justify-between gap-3 border-hover border-b p-3 pr-4 pl-4 last:border-b-0"
            >
              <div className="flex min-w-0 flex-col leading-snug">
                <span className="truncate font-mono font-semibold text-[13px]">{k.kid}</span>
                <span className="font-mono text-muted text-xs">
                  {k.algorithm} · SHA-256 {shortFingerprint(k.fingerprintSha256)}
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-muted text-xs">
                  {k.status === "retiring" && k.retiresAt
                    ? `retires ${fmt(k.retiresAt)}`
                    : `added ${fmt(k.createdAt)}`}
                </span>
                <Badge tone={k.status === "active" ? "success" : "warning"}>
                  {k.status === "active" ? "Active" : "Retiring"}
                </Badge>
                {canEdit && (
                  <div className="flex gap-1">
                    {k.status === "active" && (
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Retire key ${k.kid}`}
                        onClick={() => setTarget({ key: k, action: "retire" })}
                      >
                        Retire
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-danger"
                      aria-label={`Delete key ${k.kid}`}
                      onClick={() => setTarget({ key: k, action: "delete" })}
                    >
                      Delete
                    </Button>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="text-muted text-xs">
        The runtime signs a short-lived assertion with its private key on every token request. Keys
        can live in a KMS or the runtime's secret store; Handsal only ever sees the public half.
      </p>
      <ConfirmDialog
        open={target !== null}
        onClose={() => setTarget(null)}
        title={target?.action === "retire" ? "Retire key" : "Delete key"}
        confirmLabel={target?.action === "retire" ? "Retire key" : "Delete key"}
        danger
        loading={retire.isPending || del.isPending}
        onConfirm={confirm}
      >
        {target?.action === "retire" ? (
          <>
            Retire <strong className="font-mono">{target.key.kid}</strong>? It keeps working for the
            grace period, then stops authenticating.
          </>
        ) : (
          <>
            Permanently delete <strong className="font-mono">{target?.key.kid}</strong>? Assertions
            signed with it are rejected immediately.
          </>
        )}
      </ConfirmDialog>
    </section>
  );
}
