import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { client } from "../lib/client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from "@/components/ui/dialog";

interface ImportHostsModalProps {
  content: string;
  onClose: () => void;
  onSuccess: () => void;
}

export function ImportHostsModal({
  content,
  onClose,
  onSuccess,
}: ImportHostsModalProps) {
  const queryClient = useQueryClient();

  const importMutation = useMutation({
    mutationFn: async () => {
      return await client.importHosts({ tomlContent: content });
    },
    onSuccess: (res) => {
      toast.success(
        `Imported ${res.hostsImported} hosts, updated ${res.hostsUpdated} hosts`,
      );
      if (res.errors.length > 0) {
        res.errors.forEach((err: string) => toast.error(err));
      }
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      onSuccess();
    },
    onError: (err: Error) => {
      toast.error("Failed to import hosts: " + err.message);
    },
  });

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Import Hosts</DialogTitle>
          <DialogDescription className="text-muted-foreground pt-2">
            Import hosts from the TOML configuration file. PasswordIndex values
            are applied automatically when provided.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="flex flex-col sm:flex-row gap-2 sm:justify-between w-full">
          <Button
            type="button"
            variant="outline"
            onClick={onClose}
            disabled={importMutation.isPending}
            className="w-full sm:w-auto"
          >
            Cancel
          </Button>
          <Button
            type="button"
            onClick={() => importMutation.mutate()}
            disabled={importMutation.isPending}
            className="w-full sm:w-auto"
          >
            {importMutation.isPending ? "Importing..." : "Import Hosts"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
