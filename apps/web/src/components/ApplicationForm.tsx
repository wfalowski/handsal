import type { ApplicationDto } from "@handsal/shared";
import { AGENT_TTL_OPTIONS } from "@handsal/shared/constants";
import { type FormEvent, useState } from "react";
import { ApiRequestError } from "../lib/api";
import { useApplicationCreate } from "../lib/queries";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { Input } from "./Input";
import { SecretDoneFooter, SecretReveal } from "./SecretReveal";
import { useToast } from "./Toast";

type AuthMethod = ApplicationDto["tokenEndpointAuthMethod"];

export const SELECT_CLASS =
  "h-11 rounded-[10px] border border-line-strong bg-white pr-3 pl-3 text-ink text-sm focus:outline focus:outline-2 focus:outline-offset-1 focus:outline-accent";

/** "" = inherit the tenant default. */
const TTL_OPTIONS = [
  { value: "", label: "Inherit tenant default" },
  { value: "900", label: "15 minutes" },
  { value: "3600", label: "1 hour" },
  { value: "28800", label: "8 hours" },
  { value: "86400", label: "24 hours" },
];

/** TTL_OPTIONS plus `value` when it is not a preset (set via API), so it is shown instead of silently becoming "inherit". */
export function ttlOptions(value: string) {
  return TTL_OPTIONS.some((o) => o.value === value)
    ? TTL_OPTIONS
    : [...TTL_OPTIONS, { value, label: `${value} s` }];
}

const METHODS: { value: AuthMethod; label: string }[] = [
  { value: "client_secret_basic", label: "client_secret_basic" },
  { value: "client_secret_post", label: "client_secret_post" },
  { value: "private_key_jwt", label: "private_key_jwt" },
];

const AGENT_TTL_LABELS: Record<number, string> = {
  60: "1 minute",
  300: "5 minutes",
  900: "15 minutes",
};

export function AuthMethodRadio({
  value,
  onChange,
  agent,
  allowPrivateKey = true,
  disabled,
}: {
  value: AuthMethod;
  onChange: (v: AuthMethod) => void;
  agent?: boolean;
  /** private_key_jwt needs at least one active registered key (API: 409 no_application_key). */
  allowPrivateKey?: boolean;
  disabled?: boolean;
}) {
  return (
    <fieldset className="flex flex-col gap-1.5">
      <legend className="mb-1.5 font-medium text-[13px] text-body">Authentication method</legend>
      {METHODS.map((m) => {
        const off = disabled || (m.value === "private_key_jwt" && !allowPrivateKey);
        return (
          <label
            key={m.value}
            className="flex items-center gap-2 font-mono text-[13px] has-[:disabled]:text-faint"
          >
            <input
              type="radio"
              name="auth-method"
              className="accent-accent"
              checked={value === m.value}
              disabled={off}
              onChange={() => onChange(m.value)}
            />
            {m.value === "private_key_jwt" && agent
              ? "private_key_jwt (recommended for agents)"
              : m.label}
            {m.value === "private_key_jwt" && !allowPrivateKey && (
              <span className="font-sans text-xs">register a public key first</span>
            )}
          </label>
        );
      })}
    </fieldset>
  );
}

type Props = { tenantId: string; open: boolean; onClose: () => void };

export function ApplicationForm({ tenantId, open, onClose }: Props) {
  const [created, setCreated] = useState<{ app: ApplicationDto; secret: string } | null>(null);
  const close = () => {
    setCreated(null);
    onClose();
  };
  return (
    <Dialog
      open={open}
      onClose={close}
      title={created ? "Application created" : "New application"}
      dismissible={!created}
    >
      {created ? (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <span className="font-medium text-[13px] text-body">Client ID</span>
            <code className="break-all rounded-[10px] border border-line bg-surface pt-2.5 pr-3 pb-2.5 pl-3 font-mono text-[13px]">
              {created.app.clientId}
            </code>
          </div>
          <SecretReveal value={created.secret} hint="You won't see this again" />
          <SecretDoneFooter onDone={close} />
        </div>
      ) : (
        <Form
          tenantId={tenantId}
          onCancel={close}
          onCreated={(app, secret) => setCreated({ app, secret })}
        />
      )}
    </Dialog>
  );
}

function Form({
  tenantId,
  onCancel,
  onCreated,
}: {
  tenantId: string;
  onCancel: () => void;
  onCreated: (app: ApplicationDto, secret: string) => void;
}) {
  const toast = useToast();
  const create = useApplicationCreate(tenantId);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [method, setMethod] = useState<AuthMethod>("client_secret_basic");
  const [ttl, setTtl] = useState("");
  const [kind, setKind] = useState<"service" | "agent">("service");
  const [taken, setTaken] = useState(false);

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    create.mutate(
      {
        name: name.trim(),
        description: description.trim() || undefined,
        tokenEndpointAuthMethod: method,
        tokenTtlSeconds: ttl ? Number(ttl) : undefined,
        ...(kind === "agent" && { kind }),
      },
      {
        onSuccess: (res) => onCreated(res.application, res.clientSecret),
        onError: (err) => {
          if (err instanceof ApiRequestError && err.code === "application_exists") setTaken(true);
          else toast.error(err.message);
        },
      },
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <fieldset className="flex flex-col gap-1.5">
        <legend className="mb-1.5 font-medium text-[13px] text-body">Type</legend>
        {(
          [
            ["service", "Service"],
            ["agent", "AI agent"],
          ] as const
        ).map(([v, label]) => (
          <label key={v} className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="app-kind"
              className="accent-accent"
              checked={kind === v}
              onChange={() => {
                setKind(v);
                // Agents default to a 5-minute lease; keys can only be registered after creation.
                setMethod("client_secret_basic");
                setTtl(v === "agent" ? "300" : "");
              }}
            />
            {label}
          </label>
        ))}
      </fieldset>
      <Input
        label="Name"
        value={name}
        required
        maxLength={255}
        autoComplete="off"
        error={taken ? "An application with this name already exists" : undefined}
        onChange={(e) => {
          setName(e.target.value);
          setTaken(false);
        }}
      />
      <Input
        label="Description (optional)"
        value={description}
        maxLength={1000}
        autoComplete="off"
        onChange={(e) => setDescription(e.target.value)}
      />
      <AuthMethodRadio
        value={method}
        onChange={setMethod}
        agent={kind === "agent"}
        allowPrivateKey={false}
      />
      {kind === "agent" && (
        <p className="-mt-2 text-muted text-xs">
          Register a public key after creating the application to switch to private_key_jwt.
        </p>
      )}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="new-app-ttl" className="font-medium text-[13px] text-body">
          Access token lifetime
        </label>
        <select
          id="new-app-ttl"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          className={SELECT_CLASS}
        >
          {(kind === "agent"
            ? AGENT_TTL_OPTIONS.map((s) => ({
                value: String(s),
                label: AGENT_TTL_LABELS[s] ?? `${s} s`,
              }))
            : TTL_OPTIONS
          ).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        {kind === "agent" && (
          <p className="text-muted text-xs">Agents get short leases, one per task.</p>
        )}
      </div>
      <div className="flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" loading={create.isPending} disabled={!name.trim()}>
          Create application
        </Button>
      </div>
    </form>
  );
}
