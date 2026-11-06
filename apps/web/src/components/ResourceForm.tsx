import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { type ResourceDetail, useCreateResource, useUpdateResource } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { useToast } from "./Toast";

type Props = {
  open: boolean;
  onClose: () => void;
  tenantId: string;
  /** Prefills the form and switches it to edit mode. */
  resource?: Pick<ResourceDetail, "id" | "name" | "kind" | "audience" | "tokenTtlSeconds">;
  onSaved?: (id: string) => void;
};

const TTL_OPTIONS = [
  { value: "", label: "Inherit tenant default" },
  { value: "900", label: "15 min" },
  { value: "3600", label: "1 h" },
  { value: "28800", label: "8 h" },
  { value: "86400", label: "24 h" },
];

export function ResourceForm(props: Props) {
  return (
    <Dialog
      open={props.open}
      onClose={props.onClose}
      title={props.resource ? "Edit resource" : "New resource"}
    >
      <Fields {...props} />
    </Dialog>
  );
}

function Fields({ onClose, tenantId, resource, onSaved }: Props) {
  const toast = useToast();
  const create = useCreateResource(tenantId);
  const update = useUpdateResource(tenantId);
  const [name, setName] = useState(resource?.name ?? "");
  const [kind, setKind] = useState<"api" | "mcp">(resource?.kind ?? "api");
  const [audience, setAudience] = useState(resource?.audience ?? "");
  const [ttl, setTtl] = useState(resource?.tokenTtlSeconds ? String(resource.tokenTtlSeconds) : "");
  const [errors, setErrors] = useState<{ name?: string; audience?: string }>({});
  // A TTL outside the presets (set via API) stays selectable instead of silently resetting.
  const options = TTL_OPTIONS.some((o) => o.value === ttl)
    ? TTL_OPTIONS
    : [...TTL_OPTIONS, { value: ttl, label: `${ttl} s` }];

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setErrors({});
    const handlers = {
      onSuccess: (r: { id: string }) => {
        toast.success(resource ? "Resource updated" : `Resource ${name.trim()} created`);
        onSaved?.(r.id);
        onClose();
      },
      onError: (err: Error) => {
        if (err instanceof ApiRequestError && err.code === "audience_exists")
          setErrors({ audience: "This audience is already used by another resource" });
        else if (err instanceof ApiRequestError && err.code === "resource_name_exists")
          setErrors({ name: "A resource with this name already exists" });
        else toast.error(err.message);
      },
    };
    const base = { name: name.trim(), kind, audience: audience.trim() };
    if (resource) {
      update.mutate(
        { id: resource.id, body: { ...base, tokenTtlSeconds: ttl ? Number(ttl) : null } },
        handlers,
      );
    } else {
      create.mutate({ ...base, ...(ttl ? { tokenTtlSeconds: Number(ttl) } : {}) }, handlers);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        label="Name"
        value={name}
        required
        maxLength={255}
        autoComplete="off"
        error={errors.name}
        onChange={(e) => {
          setName(e.target.value);
          setErrors((x) => ({ ...x, name: undefined }));
        }}
      />
      <fieldset className="flex flex-col">
        <legend className="mb-1.5 font-medium text-[13px] text-body">Kind</legend>
        <div className="flex gap-4">
          {(
            [
              ["api", "API"],
              ["mcp", "MCP server"],
            ] as const
          ).map(([v, label]) => (
            <label key={v} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="kind"
                checked={kind === v}
                onChange={() => setKind(v)}
                className="accent-accent"
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>
      <Input
        label="Audience"
        value={audience}
        required
        maxLength={512}
        autoComplete="off"
        className="font-mono"
        placeholder="https://api.example.com"
        hint="The aud claim in issued tokens. A URL or URN."
        error={errors.audience}
        onChange={(e) => {
          setAudience(e.target.value);
          setErrors((x) => ({ ...x, audience: undefined }));
        }}
      />
      <div className="flex flex-col gap-1.5">
        <label htmlFor="resource-ttl" className="font-medium text-[13px] text-body">
          Token lifetime
        </label>
        <select
          id="resource-ttl"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          className="h-11 rounded-[10px] border border-line-strong bg-white pr-3.5 pl-3.5 text-ink text-sm"
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
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
          disabled={!name.trim() || !audience.trim()}
        >
          {resource ? "Save changes" : "Create resource"}
        </Button>
      </div>
    </form>
  );
}
