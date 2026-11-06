import { QueryClient } from "@tanstack/react-query";
import { createRouter, Link } from "@tanstack/react-router";
import { EmptyState } from "./components/EmptyState";
import { routeTree } from "./routeTree.gen";

export const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false } },
});

export const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  defaultNotFoundComponent: () => (
    <div className="mx-auto max-w-xl p-8">
      <EmptyState
        title="Page not found"
        description="There is nothing at this address."
        action={
          <Link to="/tenants" className="font-medium text-accent">
            Back to tenants
          </Link>
        }
      />
    </div>
  ),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
