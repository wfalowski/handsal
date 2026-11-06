import type { SigningKeyDto } from "@handsal/shared";
import { useState } from "react";
import { useRotateKey, useSigningKeys, useUpdateTenant } from "../lib/queries";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { Switch } from "./Switch";
import { Table, Td, Th } from "./Table";
import { useToast } from "./Toast";

const STATUS = {
  active: { tone: "success", label: "Active" },
  retiring: { tone: "warning", label: "Retiring" },
  retired: { tone: "neutral", label: "Retired" },
} as const;

const fmt = new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" });
const fmtDate = (iso: string) => fmt.format(new Date(iso));

type Props = { tenantId: string; keyRotationDays: number | null; canEdit: boolean };

export function SigningKeysTable({ tenantId, keyRotationDays, canEdit }: Props) {
  const toast = useToast();
  const keys = useSigningKeys(tenantId);
  const rotate = useRotateKey(tenantId);
  const update = useUpdateTenant(tenantId);
  const [confirming, setConfirming] = useState(false);

  function doRotate() {
    rotate.mutate(undefined, {
      onSuccess: () => {
        toast.success("Key rotated");
        setConfirming(false);
      },
      onError: (e) => toast.error(e.message),
    });
  }

  function setAuto(on: boolean) {
    update.mutate(
      { keyRotationDays: on ? 90 : null },
      {
        onSuccess: () => toast.success(on ? "Automatic rotation on" : "Automatic rotation off"),
        onError: (e) => toast.error(e.message),
      },
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <span className="text-muted text-sm">
          Tokens are signed with the active key. Retiring keys stay in the JWKS until their window
          ends.
        </span>
        {canEdit && (
          <Button variant="secondary" size="sm" onClick={() => setConfirming(true)}>
            Rotate key
          </Button>
        )}
      </div>
      <Table minWidth={560}>
        <thead>
          <tr>
            <Th>Key ID</Th>
            <Th>Algorithm</Th>
            <Th>Status</Th>
            <Th>Created</Th>
            <Th>Retires</Th>
          </tr>
        </thead>
        <tbody>
          {keys.data?.map((k: SigningKeyDto) => (
            <tr key={k.id}>
              <Td className="font-mono text-[13px]">{k.kid}</Td>
              <Td>{k.algorithm}</Td>
              <Td>
                <Badge tone={STATUS[k.status].tone}>{STATUS[k.status].label}</Badge>
              </Td>
              <Td className="whitespace-nowrap text-muted">{fmtDate(k.createdAt)}</Td>
              <Td className="whitespace-nowrap text-muted">
                {k.retiresAt ? fmtDate(k.retiresAt) : "—"}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
      <div className="flex items-center justify-between gap-3 rounded-[14px] border border-line bg-white p-4">
        <div className="flex flex-col">
          <span className="font-medium">Automatic rotation</span>
          <span className="text-muted text-xs">
            Generate a new key every 90 days and retire the previous one after its longest token
            lifetime.
          </span>
        </div>
        <Switch
          label="Automatic rotation"
          checked={keyRotationDays !== null}
          disabled={!canEdit || update.isPending}
          onChange={setAuto}
        />
      </div>
      <ConfirmDialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Rotate signing key?"
        confirmLabel="Rotate key"
        onConfirm={doRotate}
        loading={rotate.isPending}
      >
        A new key becomes active immediately. The current key moves to Retiring and keeps validating
        existing tokens until its window ends, then is retired.
      </ConfirmDialog>
    </div>
  );
}
