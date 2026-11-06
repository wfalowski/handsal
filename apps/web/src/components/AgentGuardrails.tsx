import type { ApplicationDto } from "@handsal/shared";
import {
  AGENT_BUDGET_MAX,
  AGENT_BUDGET_MIN,
  AGENT_MAX_SCOPES_MAX,
  AGENT_MAX_SCOPES_MIN,
  AGENT_TTL_OPTIONS,
} from "@handsal/shared/constants";
import { useState } from "react";
import { useApplicationPatch } from "../lib/queries";
import { SELECT_CLASS } from "./ApplicationForm";
import { Button } from "./Button";
import { Input } from "./Input";
import { useToast } from "./Toast";

const TTL_LABEL: Record<number, string> = { 60: "1 minute", 300: "5 minutes", 900: "15 minutes" };
const toNum = (s: string) => (s === "" ? null : Number(s));
const rangeError = (n: number | null, min: number, max: number) =>
  n !== null && (!Number.isInteger(n) || n < min || n > max) ? `Enter ${min}–${max}` : undefined;

type Props = {
  tenantId: string;
  app: ApplicationDto;
  budgetUsed: number | null;
  canEdit: boolean;
};

export function AgentGuardrails({ tenantId, app, budgetUsed, canEdit }: Props) {
  const toast = useToast();
  const update = useApplicationPatch(tenantId, app.id);
  const saved = {
    ttl: app.tokenTtlSeconds === null ? "" : String(app.tokenTtlSeconds),
    max: String(app.maxScopesPerToken ?? ""),
    budget: String(app.tokenBudgetPerHour ?? ""),
  };
  const [ttl, setTtl] = useState(saved.ttl);
  const [max, setMax] = useState(saved.max);
  const [budget, setBudget] = useState(saved.budget);
  const ttlDirty = ttl !== saved.ttl;
  const maxDirty = max !== saved.max;
  const budgetDirty = budget !== saved.budget;
  const dirty = ttlDirty || maxDirty || budgetDirty;
  const maxN = toNum(max);
  const budgetN = toNum(budget);
  const maxError = rangeError(maxN, AGENT_MAX_SCOPES_MIN, AGENT_MAX_SCOPES_MAX);
  const budgetError = rangeError(budgetN, AGENT_BUDGET_MIN, AGENT_BUDGET_MAX);
  const pct =
    budgetUsed !== null && app.tokenBudgetPerHour
      ? Math.min(100, Math.round((budgetUsed / app.tokenBudgetPerHour) * 100))
      : null;
  // Show a non-preset saved TTL instead of silently changing it.
  const ttlOpts: number[] =
    AGENT_TTL_OPTIONS.some((o) => String(o) === ttl) || ttl === ""
      ? [...AGENT_TTL_OPTIONS]
      : [...AGENT_TTL_OPTIONS, Number(ttl)];

  return (
    <section className="rounded-[14px] border border-line bg-white">
      <div className="flex flex-col border-hover border-b p-[18px] pr-5 pl-5">
        <h2 className="font-semibold text-[15px]">Guardrails</h2>
        <span className="text-muted text-[13px]">
          Limits enforced by the issuer on every token this agent requests.
        </span>
      </div>
      <div className="flex flex-col gap-4 p-5">
        <div className="flex flex-col gap-1.5">
          <label htmlFor="agent-ttl" className="font-medium text-[13px] text-body">
            Token lifetime
          </label>
          <select
            id="agent-ttl"
            value={ttl}
            disabled={!canEdit}
            onChange={(e) => setTtl(e.target.value)}
            className={SELECT_CLASS}
            aria-describedby="agent-ttl-hint"
          >
            <option value="">Inherit default</option>
            {ttlOpts.map((o) => (
              <option key={o} value={o}>
                {TTL_LABEL[o] ?? `${o} s`}
              </option>
            ))}
          </select>
          <p id="agent-ttl-hint" className="text-muted text-xs">
            Agents get short leases, one per task.
          </p>
        </div>
        <Input
          label="Max scopes per token"
          type="number"
          min={AGENT_MAX_SCOPES_MIN}
          max={AGENT_MAX_SCOPES_MAX}
          value={max}
          disabled={!canEdit}
          hint="Forces least-privilege requests."
          error={maxError}
          onChange={(e) => setMax(e.target.value)}
        />
        <div className="flex flex-col gap-1.5">
          <Input
            label="Token budget (/ hour)"
            type="number"
            min={AGENT_BUDGET_MIN}
            max={AGENT_BUDGET_MAX}
            value={budget}
            disabled={!canEdit}
            error={budgetError}
            aria-describedby={pct !== null ? "agent-budget-used" : undefined}
            onChange={(e) => setBudget(e.target.value)}
          />
          {pct !== null && (
            <>
              <div
                role="progressbar"
                aria-label="Token budget used this hour"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={pct}
                className="h-1.5 overflow-hidden rounded-full bg-hover"
              >
                <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
              </div>
              <p id="agent-budget-used" className="text-muted text-xs">
                Used this hour: {budgetUsed} of {app.tokenBudgetPerHour}
              </p>
            </>
          )}
        </div>
        {canEdit && (
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={!dirty}
              onClick={() => {
                setTtl(saved.ttl);
                setMax(saved.max);
                setBudget(saved.budget);
              }}
            >
              Discard
            </Button>
            <Button
              size="sm"
              disabled={!dirty || !!maxError || !!budgetError}
              loading={update.isPending}
              onClick={() =>
                update.mutate(
                  {
                    ...(ttlDirty && { tokenTtlSeconds: toNum(ttl) }),
                    ...(maxDirty && { maxScopesPerToken: maxN }),
                    ...(budgetDirty && { tokenBudgetPerHour: budgetN }),
                  },
                  {
                    onSuccess: () => toast.success("Guardrails saved"),
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
  );
}
