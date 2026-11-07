import { useNavigate } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";
import { useDeleteTenant, useTenantAction } from "../lib/queries";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

type Props = { tenantId: string; slug: string; paused: boolean };

function Row({ title, help, children }: { title: string; help: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-hover border-b py-3.5 last:border-b-0">
      <div className="flex flex-col">
        <span className="font-medium">{title}</span>
        <span className="text-muted text-xs">{help}</span>
      </div>
      {children}
    </div>
  );
}

export function DangerZone({ tenantId, slug, paused }: Props) {
  const toast = useToast();
  const navigate = useNavigate();
  const revoke = useTenantAction(tenantId, "revoke-all-tokens");
  const pause = useTenantAction(tenantId, "pause");
  const resume = useTenantAction(tenantId, "resume");
  const del = useDeleteTenant(tenantId);
  const [dialog, setDialog] = useState<"revoke" | "pause" | "delete" | null>(null);
  const [typed, setTyped] = useState("");
  const close = () => {
    setDialog(null);
    setTyped("");
  };

  return (
    <div className="flex flex-col px-5">
      <Row
        title="Revoke all active tokens"
        help="Stops these tokens at introspection. Servers that verify the signature locally keep them until they expire."
      >
        <Button variant="secondary" size="sm" onClick={() => setDialog("revoke")}>
          Revoke all
        </Button>
      </Row>
      <Row
        title={paused ? "Resume tenant" : "Pause tenant"}
        help={
          paused
            ? "Accept token requests again."
            : "Rejects new token requests. Tokens already issued still verify locally until they expire."
        }
      >
        {paused ? (
          <Button
            variant="secondary"
            size="sm"
            loading={resume.isPending}
            onClick={() =>
              resume.mutate(undefined, {
                onSuccess: () => toast.success("Tenant resumed"),
                onError: (e) => toast.error(e.message),
              })
            }
          >
            Resume
          </Button>
        ) : (
          <Button variant="secondary" size="sm" onClick={() => setDialog("pause")}>
            Pause
          </Button>
        )}
      </Row>
      <Row
        title="Delete tenant"
        help="Removes applications, resources, keys and history. Cannot be undone."
      >
        <Button variant="danger" size="sm" onClick={() => setDialog("delete")}>
          Delete tenant
        </Button>
      </Row>

      <ConfirmDialog
        open={dialog === "revoke"}
        onClose={close}
        title="Revoke all tokens?"
        confirmLabel="Revoke all"
        danger
        loading={revoke.isPending}
        onConfirm={() =>
          revoke.mutate(undefined, {
            onSuccess: () => {
              toast.success("All tokens revoked");
              close();
            },
            onError: (e) => toast.error(e.message),
          })
        }
      >
        Introspection will treat these tokens as inactive. A server that only checks the signature
        still accepts them until they expire.
      </ConfirmDialog>

      <ConfirmDialog
        open={dialog === "pause"}
        onClose={close}
        title="Pause tenant?"
        confirmLabel="Pause tenant"
        danger
        loading={pause.isPending}
        onConfirm={() =>
          pause.mutate(undefined, {
            onSuccess: () => {
              toast.success("Tenant paused");
              close();
            },
            onError: (e) => toast.error(e.message),
          })
        }
      >
        All token requests are rejected until you resume the tenant.
      </ConfirmDialog>

      <Dialog open={dialog === "delete"} onClose={close} title="Delete tenant">
        <form
          className="flex flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            del.mutate(typed, {
              onSuccess: () => {
                toast.success("Tenant deleted");
                close();
                navigate({ to: "/tenants" });
              },
              onError: (err) => toast.error(err.message),
            });
          }}
        >
          <p className="text-body text-sm">
            This permanently removes applications, resources, keys and history. Type{" "}
            <code className="font-mono">{slug}</code> to confirm.
          </p>
          <Input
            label="Tenant slug"
            value={typed}
            autoComplete="off"
            className="font-mono"
            onChange={(e) => setTyped(e.target.value)}
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={close}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant="danger"
              loading={del.isPending}
              disabled={typed !== slug}
            >
              Delete tenant
            </Button>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
