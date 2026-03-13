import { createFileRoute } from "@tanstack/react-router";
import { InjectsPage } from "../pages/InjectsPage";
import { z } from "zod";

const injectsSearchSchema = z.object({
  injectId: z.number().optional(),
});

export const Route = createFileRoute("/injects")({
  validateSearch: (search) => injectsSearchSchema.parse(search),
  component: InjectsPage,
});
