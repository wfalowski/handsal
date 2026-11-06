import { Link, useNavigate } from "@tanstack/react-router";
import { initials, tenantTint } from "../lib/format";
import { useApprovalCounts, useJwksHealth, useLogout } from "../lib/queries";
import type { MeTenant, MeUser } from "../lib/types";

type Props = { tenant: MeTenant; user: MeUser };

const NAV = [
  {
    to: "/t/$tenantId/applications",
    label: "Applications",
    icon: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="7" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="14" width="7" height="7" rx="1.5" />
      </>
    ),
  },
  {
    to: "/t/$tenantId/resources",
    label: "Resources",
    icon: (
      <>
        <ellipse cx="12" cy="6" rx="8" ry="3" />
        <path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6" />
        <path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" />
      </>
    ),
  },
  {
    to: "/t/$tenantId/tokens",
    label: "Tokens",
    icon: (
      <>
        <circle cx="8" cy="12" r="5" />
        <path d="M13 12h8" />
        <path d="M18 12v3" />
        <path d="M21 12v2" />
      </>
    ),
  },
  {
    to: "/t/$tenantId/approvals",
    label: "Approvals",
    icon: (
      <>
        <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z" />
        <path d="M9 12l2 2 4-4" />
      </>
    ),
  },
  {
    to: "/t/$tenantId/settings",
    label: "Settings",
    icon: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
      </>
    ),
  },
] as const;

const NAV_CLASS =
  "flex h-11 items-center gap-2.5 rounded-lg pr-2.5 pl-2.5 font-medium text-body hover:bg-hover focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent md:h-9";

export function TenantSidebar({ tenant, user }: Props) {
  const jwks = useJwksHealth(tenant);
  const logout = useLogout();
  const pending = useApprovalCounts(tenant.id).data?.pending ?? 0;
  const navigate = useNavigate();
  const tint = tenantTint(tenant.slug);
  const healthy = jwks.data === true;
  const checking = jwks.data === undefined;
  // Super-admins see every tenant as "owner" (see /api/auth/me).
  const role = user.isSuperAdmin ? "Owner" : tenant.role[0]?.toUpperCase() + tenant.role.slice(1);

  return (
    <aside className="flex shrink-0 flex-col gap-5 border-line border-b bg-white p-3 md:w-60 md:border-r md:border-b-0">
      <Link
        to="/tenants"
        aria-label="Switch tenant"
        className="flex min-h-11 items-center justify-between gap-2.5 rounded-[10px] border border-line pt-2 pr-2.5 pb-2 pl-2.5 text-ink focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          <div
            className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg font-display font-semibold text-xs"
            style={{ background: tint.tint, color: tint.ink }}
          >
            {initials(tenant.name)}
          </div>
          <div className="flex min-w-0 flex-col leading-tight">
            <span className="truncate font-semibold text-[13px]">{tenant.name}</span>
            <span className="text-[11px] text-muted">Tenant</span>
          </div>
        </div>
        <svg
          aria-hidden="true"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="#A1A1AA"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M7 9l5-5 5 5" />
          <path d="M7 15l5 5 5-5" />
        </svg>
      </Link>

      <nav aria-label="Tenant" className="flex flex-col gap-0.5">
        {NAV.map((item) => (
          <Link
            key={item.to}
            to={item.to}
            params={{ tenantId: tenant.id }}
            className={NAV_CLASS}
            activeProps={{ "aria-current": "page", className: `${NAV_CLASS} bg-hover text-accent` }}
          >
            <svg
              aria-hidden="true"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {item.icon}
            </svg>
            {item.label}
            {item.to === "/t/$tenantId/approvals" && pending > 0 && (
              <span className="ml-auto rounded-full bg-[#EEF1FF] px-[7px] font-semibold text-[#3730A3] text-[11px]">
                {pending}
                <span className="sr-only"> pending</span>
              </span>
            )}
          </Link>
        ))}
      </nav>

      <div className="flex flex-col gap-2.5 rounded-[10px] bg-surface p-3 md:mt-auto">
        <span className="text-[11px] text-muted uppercase tracking-wide">Issuer</span>
        <span className="break-all font-mono text-ink text-xs">{tenant.issuer}</span>
        <span
          className={`inline-flex items-center gap-1.5 text-xs ${healthy ? "text-success" : checking ? "text-muted" : "text-danger"}`}
        >
          <span
            aria-hidden="true"
            className={`inline-block h-[7px] w-[7px] rounded-full ${healthy ? "bg-green-500" : checking ? "bg-line" : "bg-red-500"}`}
          />
          {healthy ? "JWKS healthy" : checking ? "Checking JWKS…" : "JWKS unreachable"}
        </span>
      </div>

      <div className="flex items-center gap-2.5 pt-1.5 pr-1 pb-1.5 pl-1">
        <div
          role="img"
          aria-label={user.name}
          className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-full bg-line font-semibold text-[11px] text-body"
        >
          {initials(user.name)}
        </div>
        <div className="flex min-w-0 flex-1 flex-col leading-tight">
          <span className="truncate font-medium text-[13px]">{user.name}</span>
          <span className="text-[11px] text-muted">{role}</span>
        </div>
        <button
          type="button"
          onClick={() => logout.mutate(undefined, { onSettled: () => navigate({ to: "/login" }) })}
          className="inline-flex min-h-11 items-center text-muted text-xs hover:text-ink"
        >
          Sign out
        </button>
      </div>
    </aside>
  );
}
