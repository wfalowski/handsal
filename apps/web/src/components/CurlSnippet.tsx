import { useId, useState } from "react";
import type { GrantView } from "../lib/queries";
import { Button } from "./Button";

type Props = {
  tokenEndpoint: string;
  clientId: string;
  /** One token targets one resource, so the example uses one grant's audience and only its scopes. */
  grants: GrantView[];
};

export function CurlSnippet({ tokenEndpoint, clientId, grants }: Props) {
  const [copied, setCopied] = useState(false);
  const [index, setIndex] = useState(0);
  const selectId = useId();
  const grant = grants[index] ?? grants[0];
  const resource = grant?.resource.audience;
  const scopes = grant?.scopes.map((s) => s.name) ?? [];
  const lines = [
    `curl -X POST ${tokenEndpoint}`,
    `-u ${clientId}:$CLIENT_SECRET`,
    "-d grant_type=client_credentials",
    ...(resource ? [`-d resource=${encodeURIComponent(resource)}`] : []),
    ...(scopes.length ? [`-d scope="${scopes.join(" ")}"`] : []),
  ];
  const text = lines.join(" \\\n  ");

  async function copy() {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="flex min-w-0 flex-col gap-3 rounded-[14px] bg-[#0B0B0F] pt-[18px] pr-5 pb-[18px] pl-5 text-[#E7E7EA]">
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-sm text-white">Get a token</h2>
        <Button
          variant="ghost"
          size="sm"
          aria-label="Copy curl command"
          className="h-7 bg-[#1F1F26] text-[#A1A1AA] text-xs hover:bg-[#2a2a33]"
          onClick={copy}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      {grants.length > 1 && (
        <div className="flex items-center gap-2 text-xs">
          <label htmlFor={selectId} className="text-[#A1A1AA]">
            Resource
          </label>
          <select
            id={selectId}
            value={index}
            onChange={(e) => setIndex(Number(e.target.value))}
            className="h-8 min-w-0 flex-1 rounded-md border border-[#2a2a33] bg-[#1F1F26] pr-2 pl-2 text-[#E7E7EA]"
          >
            {grants.map((g, i) => (
              <option key={g.resource.id} value={i}>
                {g.resource.name}
              </option>
            ))}
          </select>
        </div>
      )}
      <pre className="m-0 whitespace-pre-wrap break-words font-mono text-[#D4D4D8] text-xs leading-[1.65]">
        {text}
      </pre>
    </section>
  );
}
