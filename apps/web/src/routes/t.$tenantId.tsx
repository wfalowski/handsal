import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { AppShell } from "../components/AppShell";
import { EmptyState } from "../components/EmptyState";
import { TenantSidebar } from "../components/TenantSidebar";
import { requireAuth, useMe } from "../lib/queries";

export const Route = createFileRoute("/t/$tenantId")({
  beforeLoad: ({ context }) => requireAuth(context.queryClient),
  component: TenantLayout,
});

function TenantLayout() {
  const { tenantId } = Route.useParams();
  const me = useMe();
  const tenant = me.data?.tenants.find((t) => t.id === tenantId);

  if (!me.data) return null;
  if (!tenant) {
    return (
      <div className="mx-auto max-w-xl p-8">
        <EmptyState
          title="Tenant not found"
          description="It doesn't exist, or you don't have access to it."
          action={
            <Link to="/tenants" className="font-medium text-accent">
              Back to tenants
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <AppShell sidebar={<TenantSidebar tenant={tenant} user={me.data.user} />}>
      <Outlet />
    </AppShell>
  );
}
