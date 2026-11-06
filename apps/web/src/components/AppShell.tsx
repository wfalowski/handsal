import type { ReactNode } from "react";

/** Sidebar column + content column; stacks under 768px. */
export function AppShell({ sidebar, children }: { sidebar: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-surface text-ink md:flex-row">
      {sidebar}
      <main className="flex min-w-0 flex-1 flex-col gap-7 pt-6 pr-4 pb-16 pl-4 md:pt-9 md:pr-10 md:pl-10">
        {children}
      </main>
    </div>
  );
}
