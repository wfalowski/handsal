import { type ReactNode, useEffect, useId, useRef } from "react";

type Props = {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  /** false = Escape and backdrop clicks do nothing; only an explicit button can close it. */
  dismissible?: boolean;
};

/** Native <dialog>: showModal() gives the focus trap, Escape and focus restore. Children mount only while open. */
export function Dialog({ open, onClose, title, children, dismissible = true }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  }, [open]);

  // Chrome makes a repeated Escape (no user activation in between) skip the cancelable `cancel`,
  // so also swallow Escape at keydown. Document-level: focus may sit on <body>, outside the dialog.
  useEffect(() => {
    if (!open || dismissible) return;
    const block = (e: KeyboardEvent) => {
      if (e.key === "Escape") e.preventDefault();
    };
    document.addEventListener("keydown", block, true);
    return () => document.removeEventListener("keydown", block, true);
  }, [open, dismissible]);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      // Escape fires `cancel`; a modal <dialog> never closes on backdrop clicks unless closedby="any".
      onCancel={(e) => {
        if (!dismissible) e.preventDefault();
      }}
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
