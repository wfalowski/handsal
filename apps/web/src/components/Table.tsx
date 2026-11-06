import clsx from "clsx";
import type { ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";

/** Card wrapper + <table>; compose with <thead>/<tbody>, Th and Td. */
export function Table({ children, minWidth = 640 }: { children: ReactNode; minWidth?: number }) {
  return (
    <div className="overflow-x-auto rounded-[14px] border border-line bg-white">
      <table className="w-full border-collapse" style={{ minWidth }}>
        {children}
      </table>
    </div>
  );
}

export function Th({ className, ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={clsx(
        "border-line border-b pt-3 pr-5 pb-3 pl-5 text-left font-medium text-muted text-xs uppercase tracking-wide",
        className,
      )}
      {...rest}
    />
  );
}

export function Td({ className, ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={clsx("border-hover border-b pt-3.5 pr-5 pb-3.5 pl-5", className)} {...rest} />
  );
}
