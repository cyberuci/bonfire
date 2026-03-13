import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { PasswordsPage } from "../pages/PasswordsPage";

const passwordsSearchSchema = z.object({
  category: z.string().optional(),
  highlight: z.coerce.number().optional(),
});

export const Route = createFileRoute("/passwords")({
  validateSearch: (search) => passwordsSearchSchema.parse(search),
  component: PasswordsPage,
});
