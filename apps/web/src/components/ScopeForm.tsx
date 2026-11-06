import { SCOPE_NAME_REGEX } from "@handsal/shared/constants";
import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { useCreateScope, useUpdateScope } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

type Props = {
  open: boolean;
  onClose: () => void;
  tenantId: string;
  resourceId: string;
  /** Prefills the form and switches it to edit mode. */
  scope?: { id: string; name: string; description: string | null };
};

export function ScopeForm(props: Props) {
  return (
    <Dialog
      open={props.open}
      onClose={props.onClose}
      title={props.scope ? "Edit scope" : "Add scope"}
    >
      <Fields {...props} />
    </Dialog>
  );
}

function Fields({ onClose, tenantId, resourceId, scope }: Props) {
  const toast = useToast();
  const create = useCreateScope(tenantId, resourceId);
  const update = useUpdateScope(tenantId, resourceId);
  const [name, setName] = useState(scope?.name ?? "");
  const [description, setDescription] = useState(scope?.description ?? "");
  const [taken, setTaken] = useState(false);

  const nameError = taken
    ? "This scope already exists on the resource"
    : name && !SCOPE_NAME_REGEX.test(name)
      ? "Letters, numbers, . _ : - ; must start with a letter or number"
      : undefined;

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const desc = description.trim();
    const handlers = {
      onSuccess: () => {
        toast.success(scope ? "Scope updated" : `Scope ${name} added`);
        onClose();
      },
      onError: (err: Error) => {
        if (err instanceof ApiRequestError && err.status === 409) setTaken(true);
        else toast.error(err.message);
      },
    };
    if (scope) update.mutate({ id: scope.id, body: { name, description: desc || null } }, handlers);
    else create.mutate({ name, ...(desc ? { description: desc } : {}) }, handlers);
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        label="Scope"
        value={name}
        required
        maxLength={128}
        autoComplete="off"
        className="font-mono"
        placeholder="read:invoices"
        error={nameError}
        onChange={(e) => {
          setName(e.target.value);
          setTaken(false);
        }}
      />
      <Input
        label="Description"
        value={description}
        maxLength={1000}
        autoComplete="off"
        onChange={(e) => setDescription(e.target.value)}
      />
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button
          type="submit"
          loading={create.isPending || update.isPending}
          disabled={!name || !!nameError}
        >
          {scope ? "Save changes" : "Add scope"}
        </Button>
      </div>
    </form>
  );
}
