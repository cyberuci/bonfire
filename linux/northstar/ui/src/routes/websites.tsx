import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { WebsitesPage } from "../pages/WebsitesPage";

const websiteSearchSchema = z.object({
  websiteId: z.coerce.number().optional(),
});

export const Route = createFileRoute("/websites")({
  component: WebsitesPage,
  validateSearch: (search) => websiteSearchSchema.parse(search),
});
