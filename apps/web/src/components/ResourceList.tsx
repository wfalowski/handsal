import clsx from "clsx";
import type { ResourceListItem } from "../lib/queries";
import { Badge } from "./Badge";

type Props = { resources: ResourceListItem[]; selectedId?: string; onSelect: (id: string) => void };

export function ResourceList({ resources, selectedId, onSelect }: Props) {
  return (
    <div className="flex min-w-0 flex-col gap-2">
      {resources.map((r) => (
        <button
          key={r.id}
          type="button"
          aria-pressed={r.id === selectedId}
          onClick={() => onSelect(r.id)}
          className={clsx(
            "flex w-full items-center justify-between gap-3 rounded-xl border bg-white pt-3.5 pr-4 pb-3.5 pl-4 text-left",
            r.id === selectedId ? "border-accent" : "border-line hover:border-line-strong",
          )}
        >
          <span className="flex min-w-0 flex-col leading-snug">
            <span className="flex items-center gap-2">
              <span className="truncate font-semibold text-sm">{r.name}</span>
              <Badge tone={r.kind === "mcp" ? "info" : "neutral"}>
                {r.kind === "mcp" ? "MCP" : "API"}
              </Badge>
            </span>
            <span className="truncate font-mono text-muted text-xs">{r.audience}</span>
          </span>
          <span className="whitespace-nowrap text-muted text-xs">
            {r.scopeCount} scopes · {r.appCount} apps
          </span>
        </button>
      ))}
    </div>
  );
}
