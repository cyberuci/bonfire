import { createFileRoute } from "@tanstack/react-router";
import { AllowedIPsPage } from "@/pages/AllowedIPsPage";

export const Route = createFileRoute("/allowed-ips")({
  component: AllowedIPsPage,
});
