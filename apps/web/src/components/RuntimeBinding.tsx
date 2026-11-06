import type { ApplicationDto } from "@handsal/shared";
import { AGENT_CIDRS_MAX, CIDR_REGEX } from "@handsal/shared/constants";
import { useState } from "react";
import { useApplicationPatch } from "../lib/queries";
import { Button } from "./Button";
import { Input } from "./Input";
import { useToast } from "./Toast";

const parseCidrs = (s: string) =>
  s
    .split(",")
    .map((c) => c.trim())
    .filter(Boolean);

type Props = { tenantId: string; app: ApplicationDto; canEdit: boolean };

export function RuntimeBinding({ tenantId, app, canEdit }: Props) {
  const toast = useToast();
  const update = useApplicationPatch(tenantId, app.id);
  const saved = {
    runtime: app.agentRuntime ?? "",
    cidrs: (app.allowedCidrs ?? []).join(", "),
    operator: app.operatorEmail ?? "",
  };
  const [runtime, setRuntime] = useState(saved.runtime);
  const [cidrs, setCidrs] = useState(saved.cidrs);
  const [operator, setOperator] = useState(saved.operator);
  const list = parseCidrs(cidrs);
  const bad = list.filter((c) => !CIDR_REGEX.test(c));
  const cidrError =
    bad.length > 0
      ? `Not a valid CIDR: ${bad.join(", ")}`
      : list.length > AGENT_CIDRS_MAX
        ? `At most ${AGENT_CIDRS_MAX} ranges`
        : undefined;
  const dirty = runtime !== saved.runtime || cidrs !== saved.cidrs || operator !== saved.operator;

  return (
    <section className="rounded-[14px] border border-line bg-white">
      <div className="border-hover border-b p-[18px] pr-5 pl-5">
        <h2 className="font-semibold text-[15px]">Runtime binding</h2>
      </div>
      <div className="flex flex-col gap-4 p-5">
        <Input
          label="Runtime"
          value={runtime}
          maxLength={255}
          disabled={!canEdit}
          autoComplete="off"
          onChange={(e) => setRuntime(e.target.value)}
        />
        <Input
          label="Allowed origins"
          value={cidrs}
          disabled={!canEdit}
          autoComplete="off"
          placeholder="10.40.0.0/16, 192.168.0.0/24"
          hint={`Comma-separated CIDR ranges (max ${AGENT_CIDRS_MAX}); empty allows any source. Enforcement relies on correct TRUST_PROXY settings behind a proxy, otherwise the forwarded source address can be spoofed.`}
          error={cidrError}
          onChange={(e) => setCidrs(e.target.value)}
        />
        <Input
          label="Operator"
          type="email"
          value={operator}
          maxLength={255}
          disabled={!canEdit}
          autoComplete="off"
          onChange={(e) => setOperator(e.target.value)}
        />
        {canEdit && (
          <div className="flex justify-end gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={!dirty}
              onClick={() => {
                setRuntime(saved.runtime);
                setCidrs(saved.cidrs);
                setOperator(saved.operator);
              }}
            >
              Discard
            </Button>
            <Button
              size="sm"
              disabled={!dirty || !!cidrError}
              loading={update.isPending}
              onClick={() =>
                update.mutate(
                  {
                    agentRuntime: runtime.trim() || null,
                    operatorEmail: operator.trim() || null,
                    allowedCidrs: list,
                  },
                  {
                    onSuccess: () => toast.success("Runtime binding saved"),
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
