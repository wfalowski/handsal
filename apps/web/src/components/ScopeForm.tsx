import { SCOPE_NAME_REGEX } from "@handsal/shared/constants";
import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { useCreateScope, useUpdateScope } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

export const POLICY_LABELS = {
  auto: "Auto",
  approval: "Human approval",
  never: "Never for agents",
} as const;
type Policy = keyof typeof POLICY_LABELS;

type Props = {
  open: boolean;
  onClose: () => void;
  tenantId: string;
  resourceId: string;
  /** Prefills the form and switches it to edit mode. */
  scope?: { id: string; name: string; description: string | null; agentPolicy: Policy };
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
  const [agentPolicy, setAgentPolicy] = useState<Policy>(scope?.agentPolicy ?? "auto");
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
    if (scope)
      update.mutate(
        { id: scope.id, body: { name, description: desc || null, agentPolicy } },
        handlers,
      );
    else create.mutate({ name, agentPolicy, ...(desc ? { description: desc } : {}) }, handlers);
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
      <div className="flex flex-col gap-1.5">
        <label htmlFor="scope-policy" className="font-medium text-[13px]">
          Agent policy
        </label>
        <select
          id="scope-policy"
          value={agentPolicy}
          onChange={(e) => setAgentPolicy(e.target.value as Policy)}
          className="h-11 rounded-[10px] border border-line-strong bg-white pr-3 pl-3 text-sm focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent"
        >
          {(Object.keys(POLICY_LABELS) as Policy[]).map((p) => (
            <option key={p} value={p}>
              {POLICY_LABELS[p]}
            </option>
          ))}
        </select>
      </div>
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
