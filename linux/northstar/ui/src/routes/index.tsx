import { createFileRoute } from "@tanstack/react-router";
import { HostsPage } from "../pages/HostsPage";
import { z } from "zod";

const hostsSearchSchema = z.object({
  hostId: z.number().optional(),
});

export const Route = createFileRoute("/")({
  validateSearch: (search) => hostsSearchSchema.parse(search),
  component: HostsPage,
});
