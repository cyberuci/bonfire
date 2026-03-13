import { createFileRoute } from "@tanstack/react-router";
import { FilesPage } from "@/pages/FilesPage";

export const Route = createFileRoute("/files")({
  component: FilesPage,
});
