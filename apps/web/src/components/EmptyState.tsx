import type { ReactNode } from "react";

type Props = { title: string; description?: string; action?: ReactNode };

export function EmptyState({ title, description, action }: Props) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-[14px] border border-line border-dashed bg-white p-12 text-center">
      <h2 className="font-display font-semibold text-xl tracking-tight">{title}</h2>
      {description && <p className="max-w-md text-muted">{description}</p>}
      {action}
    </div>
  );
}
