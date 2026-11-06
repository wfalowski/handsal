import { useNavigate } from "@tanstack/react-router";
import { initials } from "../lib/format";
import { useLogout, useMe } from "../lib/queries";
import { Logo } from "./Logo";

/** Top bar for pages without the tenant sidebar. `title` is the breadcrumb after "Handsal /". */
export function TopBar({ title }: { title: string }) {
  const me = useMe();
  const logout = useLogout();
  const navigate = useNavigate();
  const name = me.data?.user.name ?? "";

  return (
    <header className="flex h-14 flex-wrap items-center justify-between gap-4 border-line border-b bg-white pr-6 pl-6">
      <div className="flex items-center gap-2.5">
        <Logo />
        <span className="font-display font-semibold text-base">Handsal</span>
        <span className="text-line-strong">/</span>
        <span className="font-medium">{title}</span>
      </div>
      <div className="flex items-center gap-3">
        <a href="/docs" className="inline-flex min-h-11 items-center text-[13px] text-muted">
          Docs
        </a>
        <button
          type="button"
          onClick={() => logout.mutate(undefined, { onSettled: () => navigate({ to: "/login" }) })}
          className="inline-flex min-h-11 items-center text-[13px] text-muted"
        >
          Sign out
        </button>
        <div
          role="img"
          aria-label={`Signed in as ${name}`}
          className="flex h-8 w-8 items-center justify-center rounded-full bg-line font-semibold text-body text-xs"
        >
          {initials(name)}
        </div>
      </div>
    </header>
  );
}
