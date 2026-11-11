import clsx from "clsx";
import { useInstance } from "../lib/queries";
import { Badge } from "./Badge";

/** Instance display name plus the optional environment badge. Falls back to "Handsal". */
export function InstanceMark({ nameClassName }: { nameClassName?: string }) {
  const { data } = useInstance();
  const name = data?.name || "Handsal";
  const environment = data?.environment;

  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <span className={clsx("truncate font-display font-semibold", nameClassName)}>{name}</span>
      {environment ? (
        <span className="shrink-0">
          <Badge tone="warning">
            <span className="sr-only">Environment </span>
            {environment}
          </Badge>
        </span>
      ) : null}
    </span>
  );
}
