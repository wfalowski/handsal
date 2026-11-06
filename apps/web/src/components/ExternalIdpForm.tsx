import type { TenantDto } from "@handsal/shared";
import { useState } from "react";
import { useUpdateTenant } from "../lib/queries";
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

export function ExternalIdpForm({ tenant, canEdit }: { tenant: TenantDto; canEdit: boolean }) {
  const toast = useToast();
  const update = useUpdateTenant(tenant.id);
  const idp = tenant.externalIdp;
  const [issuer, setIssuer] = useState(idp?.issuer ?? "");
  const [jwksUri, setJwksUri] = useState(idp?.jwksUri ?? "");
  const [audience, setAudience] = useState(idp?.audience ?? "");
  const [confirmClear, setConfirmClear] = useState(false);
  const jwksError =
    jwksUri.trim() && !isHttps(jwksUri.trim()) ? "Must be an https:// URL" : undefined;
  const complete = !!issuer.trim() && !!jwksUri.trim() && !!audience.trim() && !jwksError;
  const dirty =
    issuer !== (idp?.issuer ?? "") ||
    jwksUri !== (idp?.jwksUri ?? "") ||
    audience !== (idp?.audience ?? "");

  const save = (externalIdp: TenantDto["externalIdp"], msg: string, onDone?: () => void) =>
    update.mutate(
      { externalIdp },
      {
        onSuccess: () => {
          toast.success(msg);
          onDone?.();
        },
        onError: (err) => toast.error(err.message),
      },
    );

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        save(
          { issuer: issuer.trim(), jwksUri: jwksUri.trim(), audience: audience.trim() },
          "External identity provider saved",
        );
      }}
    >
      <p className="text-muted text-[13px]">
        Subject tokens from this provider are accepted for token exchange (RFC 8693) by agents that
        may act for users.
      </p>
      <Input
        label="Issuer URL"
        type="url"
        value={issuer}
        readOnly={!canEdit}
        autoComplete="off"
        onChange={(e) => setIssuer(e.target.value)}
      />
      <Input
        label="JWKS URI"
        type="url"
        value={jwksUri}
        readOnly={!canEdit}
        autoComplete="off"
        error={jwksError}
        onChange={(e) => setJwksUri(e.target.value)}
      />
      <Input
        label="Audience"
        value={audience}
        readOnly={!canEdit}
        autoComplete="off"
        onChange={(e) => setAudience(e.target.value)}
      />
      {canEdit && (
        <div className="flex gap-2">
          <Button type="submit" loading={update.isPending} disabled={!dirty || !complete}>
            Save
          </Button>
          {idp && (
            <Button variant="secondary" onClick={() => setConfirmClear(true)}>
              Clear
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title="Clear external identity provider?"
        confirmLabel="Clear"
        danger
        loading={update.isPending}
        onConfirm={() =>
          save(null, "External identity provider cleared", () => {
            setConfirmClear(false);
            setIssuer("");
            setJwksUri("");
            setAudience("");
          })
        }
      >
        Agents will no longer be able to exchange tokens issued by this provider.
      </ConfirmDialog>
    </form>
  );
}
