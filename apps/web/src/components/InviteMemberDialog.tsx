import type { TenantRole } from "@handsal/shared";
import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { useAddMember } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { SecretDoneFooter, SecretReveal } from "./SecretReveal";
import { useToast } from "./Toast";

type Props = { open: boolean; onClose: () => void; tenantId: string };

export const ROLE_OPTIONS: TenantRole[] = ["owner", "admin", "auditor"];
export const selectClass =
  "h-11 rounded-[10px] border border-line-strong bg-white pr-3 pl-3 text-ink text-sm focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent disabled:opacity-60";

export function InviteMemberDialog({ open, onClose, tenantId }: Props) {
  const [password, setPassword] = useState<string>();
  const close = () => {
    setPassword(undefined);
    onClose();
  };
  return (
    <Dialog open={open} onClose={close} title="Invite member" dismissible={!password}>
      {password ? (
        <>
          <SecretReveal
            label="Temporary password"
            value={password}
            hint="Share it securely; it won't be shown again."
          />
          <SecretDoneFooter onDone={close} />
        </>
      ) : (
        <InviteForm tenantId={tenantId} onClose={close} onPassword={setPassword} />
      )}
    </Dialog>
  );
}

function InviteForm({
  tenantId,
  onClose,
  onPassword,
}: {
  tenantId: string;
  onClose: () => void;
  onPassword: (password: string) => void;
}) {
  const toast = useToast();
  const add = useAddMember(tenantId);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<TenantRole>("admin");
  const [emailError, setEmailError] = useState<string>();

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    add.mutate(
      { email: email.trim(), name: name.trim() || undefined, role },
      {
        onSuccess: ({ temporaryPassword }) => {
          if (temporaryPassword) onPassword(temporaryPassword);
          else {
            toast.success("Member added");
            onClose();
          }
        },
        onError: (err) => {
          if (err instanceof ApiRequestError && err.code === "already_member")
            setEmailError("This user is already a member");
          else toast.error(err.message);
        },
      },
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        label="Email"
        type="email"
        value={email}
        required
        maxLength={255}
        autoComplete="off"
        error={emailError}
        onChange={(e) => {
          setEmail(e.target.value);
          setEmailError(undefined);
        }}
      />
      <Input
        label="Name (optional)"
        value={name}
        maxLength={255}
        autoComplete="off"
        onChange={(e) => setName(e.target.value)}
      />
      <div className="flex flex-col gap-1.5">
        <label htmlFor="invite-role" className="font-medium text-[13px] text-body">
          Role
        </label>
        <select
          id="invite-role"
          className={selectClass}
          value={role}
          onChange={(e) => setRole(e.target.value as TenantRole)}
        >
          {ROLE_OPTIONS.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </div>
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button type="submit" loading={add.isPending} disabled={!email.trim()}>
          Invite
        </Button>
      </div>
    </form>
  );
}
