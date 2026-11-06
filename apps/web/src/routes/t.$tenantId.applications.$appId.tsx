import type { ApplicationDto } from "@handsal/shared";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import clsx from "clsx";
import { useState } from "react";
import {
  AuthMethodRadio,
  SELECT_CLASS,
  TTL_OPTIONS,
  ttlToValue,
} from "../components/ApplicationForm";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { CurlSnippet } from "../components/CurlSnippet";
import { Dialog } from "../components/Dialog";
import { EmptyState } from "../components/EmptyState";
import { GrantsMatrix } from "../components/GrantsMatrix";
import { Input } from "../components/Input";
import { RotateSecretDialog } from "../components/RotateSecretDialog";
import { useToast } from "../components/Toast";
import { ApiRequestError } from "../lib/api";
import { relativeTime } from "../lib/format";
import {
  useApplicationDelete,
  useApplicationDetail,
  useApplicationSetStatus,
  useApplicationTenantInfo,
  useApplicationUpdate,
  useGrantsResources,
  useMe,
} from "../lib/queries";

export const Route = createFileRoute("/t/$tenantId/applications/$appId")({
  component: ApplicationDetailPage,
});

const CARD = "rounded-[14px] border border-line bg-white";
const DOT = { issued: "bg-[#22C55E]", denied: "bg-danger", revoked: "bg-faint" };

function ApplicationDetailPage() {
  const { tenantId, appId } = Route.useParams();
  const detail = useApplicationDetail(tenantId, appId);
  const tenantInfo = useApplicationTenantInfo(tenantId);
  const grantsRes = useGrantsResources(tenantId);
  const role = useMe().data?.tenants.find((t) => t.id === tenantId)?.role;

  if (detail.isPending) return <p className="p-10 text-muted">Loading…</p>;
  if (detail.isError) {
    const notFound = detail.error instanceof ApiRequestError && detail.error.status === 404;
    return (
      <div className="mx-auto max-w-xl p-8">
        <EmptyState
          title={notFound ? "Application not found" : "Could not load application"}
          description={notFound ? undefined : detail.error.message}
          action={
            <Link
              to="/t/$tenantId/applications"
              params={{ tenantId }}
              className="font-medium text-accent"
            >
              Back to applications
            </Link>
          }
        />
      </div>
    );
  }

  const { application: app, grants, tokenEndpoint, issuer, recentTokens } = detail.data;
  const canEdit = role !== "auditor";
  const scopeNames = grants.flatMap((g) => g.scopes.map((s) => s.name));

  return (
    <div className="flex flex-col gap-6 p-6 md:p-10">
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-muted text-[13px]">
        <Link to="/t/$tenantId/applications" params={{ tenantId }}>
          Applications
        </Link>
        <span className="text-line-strong">/</span>
        <span className="font-medium text-ink">{app.name}</span>
      </nav>

      <Header tenantId={tenantId} app={app} canEdit={canEdit} />

      <div className="flex flex-wrap items-start gap-6">
        <div className="flex min-w-0 flex-[2_1_480px] flex-col gap-6">
          <Credentials tenantId={tenantId} app={app} canEdit={canEdit} />
          {grantsRes.isPending ? (
            <p className="text-muted">Loading access…</p>
          ) : grantsRes.isError ? (
            <p className="text-danger">Could not load resources.</p>
          ) : (
            <GrantsMatrix
              // Reset draft state when the server grants change.
              key={grants.map((g) => g.scopes.map((s) => s.id).join()).join("|")}
              tenantId={tenantId}
              appId={appId}
              resources={grantsRes.resources}
              grants={grants}
              canEdit={canEdit}
            />
          )}
        </div>

        <div className="flex min-w-0 flex-[1_1_300px] flex-col gap-6">
          <CurlSnippet
            tokenEndpoint={tokenEndpoint}
            clientId={app.clientId}
            scopes={scopeNames}
            resource={grants[0]?.resource.audience}
          />
          <section className={CARD}>
            <h2 className="border-hover border-b p-4 pr-5 pl-5 font-semibold text-[15px]">
              Token profile
            </h2>
            <dl className="m-0 flex flex-col pt-2 pr-5 pb-2 pl-5">
              <Fact label="Grant" value="client_credentials" mono />
              <Fact label="Format" value="JWT · ES256" mono />
              <Fact label="Issuer" value={issuer} mono />
              <Fact
                label="Introspection"
                value={
                  tenantInfo.data
                    ? tenantInfo.data.introspectionEnabled
                      ? "Enabled"
                      : "Disabled"
                    : "…"
                }
              />
              <Fact label="Rate limit" value="600 tokens / min" last />
            </dl>
          </section>
          <section className={CARD}>
            <div className="flex items-center justify-between border-hover border-b p-4 pr-5 pl-5">
              <h2 className="font-semibold text-[15px]">Recent tokens</h2>
              <Link
                to="/t/$tenantId/tokens"
                params={{ tenantId }}
                search={{ applicationId: appId }}
                className="font-medium text-[13px] text-accent"
              >
                View all
              </Link>
            </div>
            {recentTokens.length === 0 ? (
              <p className="p-5 text-muted text-sm">No tokens yet.</p>
            ) : (
              <ul className="m-0 flex list-none flex-col pt-1.5 pr-5 pb-1.5 pl-5">
                {recentTokens.map((t) => (
                  <li
                    key={t.id}
                    className="flex items-center justify-between gap-3 border-hover border-b py-2.5 last:border-b-0"
                  >
                    <div className="flex min-w-0 items-center gap-2.5">
                      <span
                        role="img"
                        aria-label={t.outcome}
                        className={clsx("h-2 w-2 flex-none rounded-full", DOT[t.outcome])}
                      />
                      <span className="truncate font-mono text-body text-xs">
                        {t.jti ? `${t.jti.slice(0, 12)}…` : t.reason}
                      </span>
                    </div>
                    <span className="whitespace-nowrap text-muted text-xs">
                      {relativeTime(t.createdAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function Fact({
  label,
  value,
  mono,
  last,
}: {
  label: string;
  value: string;
  mono?: boolean;
  last?: boolean;
}) {
  return (
    <div className={clsx("flex justify-between gap-3 py-2.5", !last && "border-hover border-b")}>
      <dt className="text-muted">{label}</dt>
      <dd
        className={clsx(
          "m-0 break-all text-right",
          mono ? "font-mono text-[12.5px]" : "text-[13px]",
        )}
      >
        {value}
      </dd>
    </div>
  );
}

function Header({
  tenantId,
  app,
  canEdit,
}: {
  tenantId: string;
  app: ApplicationDto;
  canEdit: boolean;
}) {
  const toast = useToast();
  const navigate = useNavigate();
  const setStatus = useApplicationSetStatus(tenantId, app.id);
  const del = useApplicationDelete(tenantId, app.id);
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const disabled = app.status === "disabled";

  return (
    <div className="flex flex-wrap items-start justify-between gap-4">
      <div className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="font-display font-semibold text-[28px] tracking-tight">{app.name}</h1>
          <Badge tone={disabled ? "neutral" : "success"}>{disabled ? "Disabled" : "Active"}</Badge>
        </div>
        <p className="text-muted">
          {app.description ? `${app.description} · ` : ""}created{" "}
          {new Date(app.createdAt).toLocaleDateString("en-GB", {
            day: "2-digit",
            month: "short",
            year: "numeric",
          })}
        </p>
      </div>
      {canEdit && (
        <div className="flex gap-2">
          <Button
            variant="secondary"
            size="sm"
            loading={setStatus.isPending}
            onClick={() =>
              setStatus.mutate(disabled ? "enable" : "disable", {
                onError: (err) => toast.error(err.message),
              })
            }
          >
            {disabled ? "Enable" : "Disable"}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            className="border-[#FECACA] text-danger"
            onClick={() => setConfirming(true)}
          >
            Delete
          </Button>
        </div>
      )}
      <Dialog
        open={confirming}
        onClose={() => {
          setConfirming(false);
          setTyped("");
        }}
        title="Delete application"
      >
        <p className="text-body">
          This permanently deletes <strong>{app.name}</strong> and its credentials. Type the name to
          confirm.
        </p>
        <Input label="Application name" value={typed} onChange={(e) => setTyped(e.target.value)} />
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            disabled={typed !== app.name}
            loading={del.isPending}
            onClick={() =>
              del.mutate(undefined, {
                onSuccess: () => {
                  toast.success(`Application ${app.name} deleted`);
                  navigate({ to: "/t/$tenantId/applications", params: { tenantId } });
                },
                onError: (err) => toast.error(err.message),
              })
            }
          >
            Delete application
          </Button>
        </div>
      </Dialog>
    </div>
  );
}

function Credentials({
  tenantId,
  app,
  canEdit,
}: {
  tenantId: string;
  app: ApplicationDto;
  canEdit: boolean;
}) {
  const toast = useToast();
  const update = useApplicationUpdate(tenantId, app.id);
  const [rotating, setRotating] = useState(false);
  const [copied, setCopied] = useState(false);
  const [method, setMethod] = useState(app.tokenEndpointAuthMethod);
  const [ttl, setTtl] = useState(ttlToValue(app.tokenTtlSeconds));
  const savedTtl = ttlToValue(app.tokenTtlSeconds);
  const dirty = method !== app.tokenEndpointAuthMethod || ttl !== savedTtl;
  const graceActive =
    app.previousSecretExpiresAt && new Date(app.previousSecretExpiresAt) > new Date();

  return (
    <section className={CARD}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-hover border-b p-[18px] pr-5 pl-5">
        <div className="flex flex-col">
          <h2 className="font-semibold text-[15px]">Credentials</h2>
          <span className="text-muted text-[13px]">Used with the client_credentials grant</span>
        </div>
        {canEdit && (
          <Button variant="secondary" size="sm" onClick={() => setRotating(true)}>
            Rotate secret
          </Button>
        )}
      </div>
      <div className="flex flex-col gap-4 p-5">
        <div className="flex flex-col gap-1.5">
          <span className="font-medium text-body text-xs">Client ID</span>
          <div className="flex h-[42px] items-center gap-2 rounded-[10px] border border-line bg-surface pr-1.5 pl-3.5">
            <code className="min-w-0 flex-1 truncate font-mono text-[13px]">{app.clientId}</code>
            <Button
              variant="ghost"
              size="sm"
              aria-label="Copy client ID"
              onClick={async () => {
                await navigator.clipboard.writeText(app.clientId);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
        <div className="flex flex-col gap-1.5">
          <span className="font-medium text-body text-xs">Client secret</span>
          <div className="flex h-[42px] items-center rounded-[10px] border border-line bg-surface pr-3.5 pl-3.5">
            <code className="font-mono text-[13px]" title="Hidden">
              {"•".repeat(32)}
            </code>
          </div>
          <span className="text-muted text-xs">
            {app.secretRotatedAt
              ? `Last rotated ${relativeTime(app.secretRotatedAt)}`
              : "Secret never rotated"}
            {graceActive &&
              app.previousSecretExpiresAt &&
              ` · previous secret valid until ${new Date(app.previousSecretExpiresAt).toLocaleString()}`}
          </span>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <AuthMethodRadio value={method} onChange={setMethod} />
          <div className="flex flex-col gap-1.5">
            <label htmlFor="ttl" className="font-medium text-[13px] text-body">
              Access token lifetime
            </label>
            <select
              id="ttl"
              value={ttl}
              disabled={!canEdit}
              onChange={(e) => setTtl(e.target.value)}
              className={SELECT_CLASS}
            >
              {TTL_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        {canEdit && (
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={!dirty}
              onClick={() => {
                setMethod(app.tokenEndpointAuthMethod);
                setTtl(savedTtl);
              }}
            >
              Discard
            </Button>
            <Button
              size="sm"
              disabled={!dirty}
              loading={update.isPending}
              onClick={() =>
                update.mutate(
                  { tokenEndpointAuthMethod: method, tokenTtlSeconds: ttl ? Number(ttl) : null },
                  {
                    onSuccess: () => toast.success("Settings saved"),
                    onError: (err) => toast.error(err.message),
                  },
                )
              }
            >
              Save
            </Button>
          </div>
        )}
      </div>
      <RotateSecretDialog
        tenantId={tenantId}
        appId={app.id}
        open={rotating}
        onClose={() => setRotating(false)}
      />
    </section>
  );
}
