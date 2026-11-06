import type { ApplicationDto } from "@handsal/shared";
import { DELEGATION_SCOPE_MODES, MAY_ACT_FOR } from "@handsal/shared/constants";
import { useState } from "react";
import { type GrantView, useApplicationUpdate } from "../lib/queries";
import { Button } from "./Button";
import { ClaimsPreview } from "./ClaimsPreview";
import { useToast } from "./Toast";

type MayActFor = (typeof MAY_ACT_FOR)[keyof typeof MAY_ACT_FOR];
type Mode = (typeof DELEGATION_SCOPE_MODES)[keyof typeof DELEGATION_SCOPE_MODES];

const SUBJECTS: Record<MayActFor, string> = {
  users: "Users from the configured identity provider",
  tenant: "Any client in this tenant",
  services: "Service clients only",
};
const MODES: Record<Mode, { label: string; hint: string }> = {
  intersection: {
    label: "Intersection of user's and agent's scopes",
    hint: "The token carries only scopes both the subject and the agent hold.",
  },
  agent_only: {
    label: "Agent's scopes only",
    hint: "The token carries the agent's granted scopes regardless of the subject's.",
  },
};

type Props = {
  tenantId: string;
  app: ApplicationDto;
  issuer: string;
  grants: GrantView[];
  canEdit: boolean;
};

export function DelegationSettings({ tenantId, app, issuer, grants, canEdit }: Props) {
  const toast = useToast();
  const update = useApplicationUpdate(tenantId, app.id);
  const savedActFor: MayActFor[] = app.mayActFor ?? [];
  const savedMode: Mode = app.delegationScopeMode ?? "intersection";
  const [actFor, setActFor] = useState<MayActFor[]>(savedActFor);
  const [mode, setMode] = useState<Mode>(savedMode);
  const dirty =
    mode !== savedMode ||
    actFor.length !== savedActFor.length ||
    actFor.some((v) => !savedActFor.includes(v));

  return (
    <>
      <section className="rounded-[14px] border border-line bg-white">
        <div className="flex flex-col border-hover border-b p-[18px] pr-5 pl-5">
          <h2 className="font-semibold text-[15px]">Delegation</h2>
          <span className="text-muted text-[13px]">
            Let the agent act on behalf of a user or another service via token exchange (RFC 8693).
            The token carries both identities.
          </span>
        </div>
        <div className="flex flex-col gap-5 p-5">
          <fieldset className="flex flex-col gap-1">
            <legend className="mb-1 font-medium text-[13px] text-body">May act for</legend>
            {Object.values(MAY_ACT_FOR).map((v) => (
              <label key={v} className="flex min-h-11 items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={actFor.includes(v)}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setActFor(e.target.checked ? [...actFor, v] : actFor.filter((x) => x !== v))
                  }
                />
                {SUBJECTS[v]}
              </label>
            ))}
            <p className="text-muted text-xs">
              Leave all unchecked to disable token exchange for this agent.
            </p>
          </fieldset>
          <fieldset className="flex flex-col gap-1">
            <legend className="mb-1 font-medium text-[13px] text-body">Resulting scopes</legend>
            {Object.values(DELEGATION_SCOPE_MODES).map((m) => (
              <label key={m} className="flex min-h-11 items-start gap-2 py-2.5 text-sm">
                <input
                  type="radio"
                  name="delegation-scope-mode"
                  className="mt-1"
                  checked={mode === m}
                  disabled={!canEdit}
                  onChange={() => setMode(m)}
                />
                <span className="flex flex-col">
                  {MODES[m].label}
                  <span className="text-muted text-xs">{MODES[m].hint}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {canEdit && (
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                size="sm"
                disabled={!dirty}
                onClick={() => {
                  setActFor(savedActFor);
                  setMode(savedMode);
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
                    { mayActFor: actFor, delegationScopeMode: mode },
                    {
                      onSuccess: () => toast.success("Delegation settings saved"),
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
      </section>
      <ClaimsPreview
        issuer={issuer}
        app={app}
        audience={grants[0]?.resource.audience ?? "<resource audience>"}
        scopes={[...new Set(grants.flatMap((g) => g.scopes.map((s) => s.name)))]}
        ttlSeconds={app.tokenTtlSeconds ?? 300}
      />
    </>
  );
}
