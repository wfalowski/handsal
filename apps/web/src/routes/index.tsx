import { createFileRoute, redirect } from "@tanstack/react-router";
import { requireAuth } from "../lib/queries";

export const Route = createFileRoute("/")({
  beforeLoad: async ({ context }) => {
    await requireAuth(context.queryClient);
    throw redirect({ to: "/tenants" });
  },
});
