import type { TenantDto } from "@handsal/shared";
import { useState } from "react";
import { type TenantPatch, useUpdateTenant } from "../lib/queries";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { ConfirmDialog } from "./ConfirmDialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

const isHttps = (s: string) => {
  try {
    return new URL(s).protocol === "https:";
  } catch {
    return false;
  }
};

const MIN_SECRET = 16;

export function ApprovalWebhookForm({ tenant, canEdit }: { tenant: TenantDto; canEdit: boolean }) {
  const toast = useToast();
  const update = useUpdateTenant(tenant.id);
  const savedUrl = tenant.approvalWebhookUrl ?? "";
  const secretSet = tenant.approvalWebhookSecretSet === true;
  const [url, setUrl] = useState(savedUrl);
  const [secret, setSecret] = useState("");
  const [confirmRemove, setConfirmRemove] = useState(false);
  const urlError = url.trim() && !isHttps(url.trim()) ? "Must be an https:// URL" : undefined;
  const secretError =
    secret && secret.length < MIN_SECRET ? `At least ${MIN_SECRET} characters` : undefined;
  const dirty = url.trim() !== savedUrl || secret !== "";

  const save = (patch: TenantPatch, msg: string, onDone?: () => void) =>
    update.mutate(patch, {
      onSuccess: () => {
        toast.success(msg);
        onDone?.();
      },
      onError: (err) => toast.error(err.message),
    });

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        const patch: TenantPatch = {};
        if (url.trim() !== savedUrl) patch.approvalWebhookUrl = url.trim() || null;
        if (secret) patch.approvalWebhookSecret = secret;
        save(patch, "Approval notifications saved", () => setSecret(""));
      }}
    >
      <p className="text-muted text-[13px]">
        Handsal POSTs <code>approval.pending</code> events here; the body is signed with HMAC-SHA256
        in the X-Handsal-Signature header. Slack incoming webhook URLs are supported.
      </p>
      <Input
        label="Webhook URL"
        type="url"
        value={url}
        readOnly={!canEdit}
        autoComplete="off"
        error={urlError}
        hint="Leave empty to disable notifications."
        onChange={(e) => setUrl(e.target.value)}
      />
      <div className="flex flex-col gap-1.5">
        {secretSet && (
          <div>
            <Badge tone="success">Secret set</Badge>
          </div>
        )}
        <Input
          label="Signing secret"
          type="password"
          value={secret}
          readOnly={!canEdit}
          autoComplete="new-password"
          placeholder={secretSet ? "Leave blank to keep the current secret" : undefined}
          error={secretError}
          onChange={(e) => setSecret(e.target.value)}
        />
      </div>
      {canEdit && (
        <div className="flex gap-2">
          <Button
            type="submit"
            loading={update.isPending}
            disabled={!dirty || !!urlError || !!secretError}
          >
            Save
          </Button>
          <Button
            variant="secondary"
            disabled={!dirty}
            onClick={() => {
              setUrl(savedUrl);
              setSecret("");
            }}
          >
            Discard
          </Button>
          {secretSet && (
            <Button variant="secondary" onClick={() => setConfirmRemove(true)}>
              Remove secret
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        title="Remove signing secret?"
        confirmLabel="Remove"
        danger
        loading={update.isPending}
        onConfirm={() =>
          save({ approvalWebhookSecret: null }, "Signing secret removed", () => {
            setConfirmRemove(false);
            setSecret("");
          })
        }
      >
        Webhook requests will be sent unsigned until a new secret is set.
      </ConfirmDialog>
    </form>
  );
}
