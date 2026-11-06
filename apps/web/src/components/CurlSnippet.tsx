import { useState } from "react";
import { Button } from "./Button";

type Props = {
  tokenEndpoint: string;
  clientId: string;
  scopes: string[];
  /** Audience of the first granted resource. */
  resource?: string;
};

export function CurlSnippet({ tokenEndpoint, clientId, scopes, resource }: Props) {
  const [copied, setCopied] = useState(false);
  const lines = [
    `curl -X POST ${tokenEndpoint}`,
    `-u ${clientId}:$CLIENT_SECRET`,
    "-d grant_type=client_credentials",
    ...(resource ? [`-d resource=${resource}`] : []),
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
      <pre className="m-0 whitespace-pre-wrap break-words font-mono text-[#D4D4D8] text-xs leading-[1.65]">
        {text}
      </pre>
    </section>
  );
}
