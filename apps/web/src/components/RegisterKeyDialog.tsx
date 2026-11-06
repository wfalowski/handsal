import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { useRegisterApplicationKey } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";

type Props = { tenantId: string; appId: string; open: boolean; onClose: () => void };

export function RegisterKeyDialog({ tenantId, appId, open, onClose }: Props) {
  const register = useRegisterApplicationKey(tenantId, appId);
  const [kid, setKid] = useState("");
  const [pem, setPem] = useState("");
  const [error, setError] = useState<{ field: "kid" | "pem"; message: string } | null>(null);

  function close() {
    setKid("");
    setPem("");
    setError(null);
    register.reset();
    onClose();
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    register.mutate(
      { kid: kid.trim(), publicKeyPem: pem.trim() },
      {
        onSuccess: close,
        onError: (err) => {
          if (err instanceof ApiRequestError && err.status === 409) {
            setError({ field: "kid", message: err.message });
          } else setError({ field: "pem", message: err.message });
        },
      },
    );
  }

  const pemId = "register-key-pem";
  return (
    <Dialog open={open} onClose={close} title="Register public key">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Input
          label="Key ID"
          value={kid}
          required
          maxLength={128}
          pattern="[A-Za-z0-9._:\-]+"
          autoComplete="off"
          hint="Sent as the kid header of the runtime's assertions."
          error={error?.field === "kid" ? error.message : undefined}
          onChange={(e) => {
            setKid(e.target.value);
            setError(null);
          }}
        />
        <div className="flex flex-col gap-1.5">
          <label htmlFor={pemId} className="font-medium text-[13px] text-body">
            Public key
          </label>
          <textarea
            id={pemId}
            value={pem}
            required
            maxLength={4096}
            rows={7}
            spellCheck={false}
            placeholder={"-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----"}
            aria-invalid={error?.field === "pem" ? true : undefined}
            aria-describedby={`${pemId}-help`}
            onChange={(e) => {
              setPem(e.target.value);
              setError(null);
            }}
            className="rounded-[10px] border border-line-strong bg-white p-3 font-mono text-ink text-xs placeholder:text-faint focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent"
          />
          <p
            id={`${pemId}-help`}
            className={error?.field === "pem" ? "text-danger text-xs" : "text-muted text-xs"}
          >
            {error?.field === "pem"
              ? error.message
              : "P-256 (ES256) public key in SPKI PEM format. Handsal never sees the private half."}
          </p>
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" loading={register.isPending} disabled={!kid.trim() || !pem.trim()}>
            Register key
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
