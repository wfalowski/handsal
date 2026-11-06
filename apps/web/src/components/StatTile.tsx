import clsx from "clsx";
import type { ReactNode } from "react";

type Props = { label: string; value: ReactNode; sub: ReactNode; subTone?: "success" | "muted" };

export function StatTile({ label, value, sub, subTone = "muted" }: Props) {
  return (
    <div className="flex flex-col gap-1.5 rounded-[14px] border border-line bg-white pt-[18px] pr-5 pb-[18px] pl-5">
      <span className="text-muted text-xs">{label}</span>
      <span className="font-display font-semibold text-[28px] tracking-tight">{value}</span>
      <span className={clsx("text-xs", subTone === "success" ? "text-success" : "text-muted")}>
        {sub}
      </span>
    </div>
  );
}
