import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { type ReactNode, useEffect, useState } from "react";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { DangerZone } from "../components/DangerZone";
import { Input } from "../components/Input";
import { selectClass } from "../components/InviteMemberDialog";
import { MembersTable } from "../components/MembersTable";
import { SETTINGS_SECTIONS, SettingsNav } from "../components/SettingsNav";
import { SigningKeysTable } from "../components/SigningKeysTable";
import { Switch } from "../components/Switch";
import { useToast } from "../components/Toast";
import { type TenantDetail, useTenant, useUpdateTenant } from "../lib/queries";

export const Route = createFileRoute("/t/$tenantId/settings")({
  validateSearch: (s: Record<string, unknown>): { section?: string } => ({
    section:
      typeof s.section === "string" && SETTINGS_SECTIONS.some((x) => x.id === s.section)
        ? s.section
        : undefined,
  }),
  component: SettingsPage,
});

const TTL_OPTIONS = [
  { value: 900, label: "15 minutes" },
  { value: 3600, label: "1 hour" },
  { value: 28800, label: "8 hours" },
  { value: 86400, label: "24 hours" },
];

function Section({
  id,
  title,
  description,
  danger,
  children,
}: {
  id: string;
  title: string;
  description?: string;
  danger?: boolean;
  children: ReactNode;
}) {
  return (
    <section
      id={id}
      aria-labelledby={`${id}-title`}
      className={`flex scroll-mt-6 flex-col gap-4 rounded-[14px] border bg-white p-5 ${danger ? "border-red-200" : "border-line"}`}
    >
      <div className="flex flex-col">
        <h2
          id={`${id}-title`}
          className={`font-semibold text-[15px] ${danger ? "text-danger" : "text-ink"}`}
        >
          {title}
        </h2>
        {description && <span className="text-muted text-[13px]">{description}</span>}
      </div>
      {children}
    </section>
  );
}

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-col gap-1.5">
      <span className="font-medium text-[13px] text-body">{label}</span>
      <div className="flex items-center gap-2">
        <code className="min-w-0 flex-1 break-all rounded-[10px] border border-line bg-surface pt-2.5 pr-3 pb-2.5 pl-3 font-mono text-[13px]">
          {value}
        </code>
        <Button
          variant="secondary"
          size="sm"
          onClick={async () => {
            await navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
    </div>
  );
}

function SettingsPage() {
  const { tenantId } = Route.useParams();
  const { section } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const tenant = useTenant(tenantId);

  // Scroll to the anchor once the sections have rendered (and on every ?section= change).
  const ready = !!tenant.data;
  useEffect(() => {
    if (!ready || !section) return;
    // rAF: the router's own scroll handling runs after navigation and would undo an immediate scroll.
    const raf = requestAnimationFrame(() =>
      document.getElementById(section)?.scrollIntoView({ block: "start" }),
    );
    return () => cancelAnimationFrame(raf);
  }, [ready, section]);

  if (!tenant.data) return null;
  const t = tenant.data;
  const isOwner = t.role === "owner";
  const canEdit = t.role !== "auditor";

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 p-6 md:p-8">
      <header className="flex items-center gap-3">
        <h1 className="font-display font-semibold text-2xl tracking-tight">Settings</h1>
        {t.status === "paused" && <Badge tone="warning">Paused</Badge>}
      </header>
      <div className="grid gap-8 md:grid-cols-[180px_1fr]">
        <SettingsNav
          active={section}
          showDanger={isOwner}
          onSelect={(id) => navigate({ search: { section: id }, replace: true })}
        />
        <div className="flex min-w-0 flex-col gap-6">
          <Section id="general" title="General">
            <GeneralForm tenant={t} canEdit={canEdit} />
          </Section>
          <Section id="signing-keys" title="Signing keys">
            <SigningKeysTable
              tenantId={tenantId}
              keyRotationDays={t.keyRotationDays}
              canEdit={canEdit}
            />
          </Section>
          <Section id="token-defaults" title="Token defaults">
            <TokenDefaultsForm tenant={t} canEdit={canEdit} />
          </Section>
          <Section id="members" title="Members">
            <MembersTable tenantId={tenantId} canEdit={isOwner} />
          </Section>
          {isOwner && (
            <Section
              id="danger"
              title="Danger zone"
              description="Actions here affect every application in this tenant immediately."
              danger
            >
              <DangerZone tenantId={tenantId} slug={t.slug} paused={t.status === "paused"} />
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}

function GeneralForm({ tenant, canEdit }: { tenant: TenantDetail; canEdit: boolean }) {
  const toast = useToast();
  const update = useUpdateTenant(tenant.id);
  const [name, setName] = useState(tenant.name);
  useEffect(() => setName(tenant.name), [tenant.name]);
  const dirty = name.trim() !== tenant.name && name.trim() !== "";

  return (
    <form
      className="flex flex-col gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        update.mutate(
          { name: name.trim() },
          {
            onSuccess: () => toast.success("Settings saved"),
            onError: (err) => toast.error(err.message),
          },
        );
      }}
    >
      <Input
        label="Name"
        value={name}
        maxLength={255}
        readOnly={!canEdit}
        onChange={(e) => setName(e.target.value)}
      />
      <Input label="Slug" value={tenant.slug} readOnly className="font-mono" />
      <CopyField label="Issuer URL" value={tenant.issuer} />
      <p className="text-muted text-xs">
        Discovery at <code className="font-mono">/.well-known/openid-configuration</code>, keys at{" "}
        <code className="font-mono">/.well-known/jwks.json</code>
        <br />
        <span className="font-mono">{tenant.discoveryUrl}</span>
        <br />
        <span className="font-mono">{tenant.jwksUrl}</span>
      </p>
      {canEdit && (
        <div>
          <Button type="submit" loading={update.isPending} disabled={!dirty}>
            Save
          </Button>
        </div>
      )}
    </form>
  );
}

function TokenDefaultsForm({ tenant, canEdit }: { tenant: TenantDetail; canEdit: boolean }) {
  const toast = useToast();
  const update = useUpdateTenant(tenant.id);
  const [ttl, setTtl] = useState(tenant.defaultTokenTtlSeconds);
  const [introspection, setIntrospection] = useState(tenant.introspectionEnabled);
  useEffect(() => {
    setTtl(tenant.defaultTokenTtlSeconds);
    setIntrospection(tenant.introspectionEnabled);
  }, [tenant.defaultTokenTtlSeconds, tenant.introspectionEnabled]);
  const dirty =
    ttl !== tenant.defaultTokenTtlSeconds || introspection !== tenant.introspectionEnabled;
  const options = TTL_OPTIONS.some((o) => o.value === ttl)
    ? TTL_OPTIONS
    : [...TTL_OPTIONS, { value: ttl, label: `${ttl} seconds` }];

  return (
    <form
      className="flex flex-col gap-5"
      onSubmit={(e) => {
        e.preventDefault();
        update.mutate(
          { defaultTokenTtlSeconds: ttl, introspectionEnabled: introspection },
          {
            onSuccess: () => toast.success("Settings saved"),
            onError: (err) => toast.error(err.message),
          },
        );
      }}
    >
      <div className="flex flex-col gap-1.5">
        <label htmlFor="token-ttl" className="font-medium text-[13px] text-body">
          Default token lifetime
        </label>
        <select
          id="token-ttl"
          className={`${selectClass} max-w-xs`}
          value={ttl}
          disabled={!canEdit}
          onChange={(e) => setTtl(Number(e.target.value))}
        >
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>
      <fieldset className="flex flex-col gap-2">
        <legend className="font-medium text-[13px] text-body">Token format</legend>
        <label className="flex items-center gap-2 text-sm">
          <input type="radio" name="token-format" checked readOnly />
          JWT (self-contained)
        </label>
        <label className="flex items-center gap-2 text-muted text-sm">
          <input type="radio" name="token-format" disabled />
          Opaque (introspection only)
          <Badge>coming soon</Badge>
        </label>
      </fieldset>
      <div className="flex items-center justify-between gap-3">
        <div className="flex flex-col">
          <span className="font-medium">Token introspection endpoint</span>
          <span className="text-muted text-xs">
            Expose RFC 7662 /oauth/introspect for resource servers that cannot verify JWTs locally.
          </span>
        </div>
        <Switch
          label="Token introspection endpoint"
          checked={introspection}
          disabled={!canEdit}
          onChange={setIntrospection}
        />
      </div>
      {canEdit && (
        <div>
          <Button type="submit" loading={update.isPending} disabled={!dirty}>
            Save
          </Button>
        </div>
      )}
    </form>
  );
}
