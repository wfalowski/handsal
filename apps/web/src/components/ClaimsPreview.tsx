import type { ApplicationDto } from "@handsal/shared";

type Props = {
  issuer: string;
  app: ApplicationDto;
  audience: string;
  scopes: string[];
  ttlSeconds: number;
};

// Illustrative only: RFC 8693 shape, sub = the subject, act.sub = the agent.
export function ClaimsPreview({ issuer, app, audience, scopes, ttlSeconds }: Props) {
  const claims = {
    iss: issuer,
    sub: "<subject sub>",
    act: { sub: app.clientId },
    aud: audience,
    scope: scopes.join(" "),
    client_kind: "agent",
    task_id: "run_01JBXA…",
  };
  return (
    <section className="flex min-w-0 flex-col gap-3 rounded-[14px] bg-[#0B0B0F] p-5 text-[#E7E7EA]">
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-sm text-white">Token claims preview</h2>
        <span className="font-mono text-[#71717A] text-[11px]">ES256 · {ttlSeconds} s</span>
      </div>
      <pre className="whitespace-pre-wrap break-words font-mono text-[#D4D4D8] text-xs leading-[1.65]">
        {JSON.stringify(claims, null, 2)}
      </pre>
    </section>
  );
}
