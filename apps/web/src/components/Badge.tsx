import clsx from "clsx";
import type { ReactNode } from "react";

type Props = {
  tone?: "success" | "neutral" | "warning" | "danger" | "info";
  children: ReactNode;
};

const tones = {
  success: "bg-success-bg text-success",
  neutral: "bg-hover text-muted",
  warning: "bg-warning-bg text-warning",
  danger: "bg-danger-bg text-danger",
  info: "bg-info-bg text-info",
};

export function Badge({ tone = "neutral", children }: Props) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full pt-[3px] pr-2 pb-[3px] pl-2 font-medium text-xs",
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}
