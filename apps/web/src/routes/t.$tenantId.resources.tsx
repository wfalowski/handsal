import { createFileRoute } from "@tanstack/react-router";
import { EmptyState } from "../components/EmptyState";

export const Route = createFileRoute("/t/$tenantId/resources")({
  component: () => <EmptyState title="Resources" />,
});
