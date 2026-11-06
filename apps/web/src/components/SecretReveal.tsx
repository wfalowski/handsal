import { useState } from "react";
import { Button } from "./Button";

type Props = {
  value: string;
  label?: string;
  hint?: string;
};

/** Footer for a dialog showing a once-only secret: the explicit button is the only way out. */
export function SecretDoneFooter({ onDone }: { onDone: () => void }) {
  return (
    <div className="flex items-center justify-end gap-3">
      <p className="text-muted text-xs">Copy it now — this dialog won't show it again.</p>
      <Button onClick={onDone}>Done</Button>
    </div>
  );
}

export function SecretReveal({ value, label = "Client secret", hint }: Props) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex flex-col gap-1.5">
      <span className="font-medium text-[13px] text-body">{label}</span>
      <div className="flex flex-wrap items-center gap-2">
        <code className="min-w-0 flex-1 break-all rounded-[10px] border border-line bg-surface pt-2.5 pr-3 pb-2.5 pl-3 font-mono text-[13px]">
          {revealed ? value : "•".repeat(32)}
        </code>
        <Button variant="secondary" size="sm" onClick={() => setRevealed((r) => !r)}>
          {revealed ? "Hide" : "Reveal"}
        </Button>
        <Button variant="secondary" size="sm" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      {hint && (
        <p role="note" className="text-warning text-xs">
          {hint}
        </p>
      )}
    </div>
  );
}
