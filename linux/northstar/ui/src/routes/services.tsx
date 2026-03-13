import { createFileRoute } from "@tanstack/react-router";
import { ServicesPage } from "../pages/ServicesPage";
import { z } from "zod";

const servicesSearchSchema = z.object({
  serviceId: z.number().optional(),
});

export const Route = createFileRoute("/services")({
  validateSearch: (search) => servicesSearchSchema.parse(search),
  component: ServicesPage,
});
