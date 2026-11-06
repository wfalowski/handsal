import { useState } from "react";
import { useApplicationRotateSecret } from "../lib/queries";
import { SELECT_CLASS } from "./ApplicationForm";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { SecretDoneFooter, SecretReveal } from "./SecretReveal";
import { useToast } from "./Toast";

const GRACE = [
  { value: 0, label: "Immediately (no grace period)" },
  { value: 3600, label: "1 hour" },
  { value: 86400, label: "24 hours" },
  { value: 604800, label: "7 days" },
];

type Props = { tenantId: string; appId: string; open: boolean; onClose: () => void };

export function RotateSecretDialog({ tenantId, appId, open, onClose }: Props) {
  const toast = useToast();
  const rotate = useApplicationRotateSecret(tenantId, appId);
  const [grace, setGrace] = useState(86400);
  const [result, setResult] = useState<{ secret: string; until: string | null } | null>(null);

  function close() {
    setResult(null);
    rotate.reset();
    onClose();
  }

  return (
    <Dialog open={open} onClose={close} title="Rotate client secret" dismissible={!result}>
      {result ? (
        <div className="flex flex-col gap-4">
          <SecretReveal
            value={result.secret}
            label="New client secret"
            hint="You won't see this again"
          />
          {result.until && (
            <p className="text-muted text-xs">
              Previous secret valid until {new Date(result.until).toLocaleString()}.
            </p>
          )}
          <SecretDoneFooter onDone={close} />
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          <p className="text-body">
            A new secret is generated. The current one keeps working for the grace period so you can
            roll it out without downtime.
          </p>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="grace" className="font-medium text-[13px] text-body">
              Keep the previous secret valid for
            </label>
            <select
              id="grace"
              value={grace}
              onChange={(e) => setGrace(Number(e.target.value))}
              className={SELECT_CLASS}
            >
              {GRACE.map((g) => (
                <option key={g.value} value={g.value}>
                  {g.label}
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={close}>
              Cancel
            </Button>
            <Button
              loading={rotate.isPending}
              onClick={() =>
                rotate.mutate(grace, {
                  onSuccess: (r) =>
                    setResult({ secret: r.clientSecret, until: r.previousSecretExpiresAt }),
                  onError: (err) => toast.error(err.message),
                })
              }
            >
              Rotate secret
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
