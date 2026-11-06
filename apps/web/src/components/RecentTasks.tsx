import clsx from "clsx";
import { relativeTime } from "../lib/format";
import { useTasks } from "../lib/queries";

export function RecentTasks({
  tenantId,
  applicationId,
  selected,
  onSelect,
}: {
  tenantId: string;
  applicationId?: string;
  selected?: string;
  onSelect: (taskId: string | undefined) => void;
}) {
  const tasks = useTasks(tenantId, { applicationId, limit: 5 });
  return (
    <section
      aria-labelledby="recent-tasks"
      className="flex flex-col gap-1 rounded-[14px] border border-line bg-white p-4"
    >
      <div className="flex items-center justify-between pr-1 pl-1">
        <h2 id="recent-tasks" className="font-display font-semibold text-base">
          Recent tasks
        </h2>
        <button
          type="button"
          onClick={() => onSelect(undefined)}
          className="inline-flex h-11 items-center text-accent text-sm hover:underline"
        >
          View all
        </button>
      </div>
      {tasks.isPending ? (
        <p className="p-2 text-muted text-sm">Loading…</p>
      ) : tasks.isError ? (
        <p role="alert" className="p-2 text-danger text-sm">
          Couldn't load tasks: {tasks.error.message}
        </p>
      ) : tasks.data.length === 0 ? (
        <p className="p-2 text-muted text-sm">No agent tasks in the last 24 hours.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col p-0">
          {tasks.data.map((t) => {
            const dot =
              t.deniedCount === 0
                ? "bg-success"
                : t.deniedCount >= t.tokenCount
                  ? "bg-danger"
                  : "bg-warning";
            return (
              <li key={t.taskId}>
                <button
                  type="button"
                  aria-pressed={selected === t.taskId}
                  onClick={() => onSelect(t.taskId)}
                  className={clsx(
                    "flex min-h-11 w-full items-center gap-3 rounded-[10px] pt-1.5 pr-2 pb-1.5 pl-2 text-left hover:bg-hover",
                    selected === t.taskId && "bg-hover",
                  )}
                >
                  <span aria-hidden="true" className={clsx("size-2 shrink-0 rounded-full", dot)} />
                  <span className="flex min-w-0 flex-1 flex-col">
                    <code className="truncate font-mono text-[13px]">{t.taskId}</code>
                    <span className="truncate text-muted text-xs">
                      {t.actorSub ? `for ${t.actorSub}` : t.scopes.join(" · ")}
                    </span>
                  </span>
                  <span className="shrink-0 text-muted text-xs">{relativeTime(t.lastSeenAt)}</span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
