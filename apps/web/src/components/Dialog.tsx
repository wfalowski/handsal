import { type ReactNode, useEffect, useId, useRef } from "react";

type Props = {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
};

/** Native <dialog>: showModal() gives the focus trap, Escape and focus restore. Children mount only while open. */
export function Dialog({ open, onClose, title, children }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      className="w-[calc(100%-32px)] max-w-md rounded-[14px] border border-line bg-white p-0 text-ink shadow-xl backdrop:bg-black/40"
    >
      {open && (
        <div className="flex flex-col gap-5 p-6">
          <h2 id={titleId} className="font-display font-semibold text-xl tracking-tight">
            {title}
          </h2>
          {children}
        </div>
      )}
    </dialog>
  );
}
