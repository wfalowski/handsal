import type { QueryClient } from "@tanstack/react-query";
import { QueryClientProvider } from "@tanstack/react-query";
import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import { useEffect } from "react";
import { ToastProvider } from "../components/Toast";
import { instanceQueryOptions, useInstance } from "../lib/queries";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  loader: ({ context }) => {
    void context.queryClient.prefetchQuery(instanceQueryOptions);
  },
  component: Root,
});

function Root() {
  const { queryClient } = Route.useRouteContext();
  return (
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <InstanceDocumentTitle />
        <Outlet />
      </ToastProvider>
    </QueryClientProvider>
  );
}

function InstanceDocumentTitle() {
  const { data } = useInstance();
  const name = data?.name || "Handsal";
  const environment = data?.environment ?? null;
  useEffect(() => {
    document.title = environment ? `${name} · ${environment}` : name;
  }, [name, environment]);
  return null;
}
