import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ShieldCheck, Plus, Trash2 } from "lucide-react";
import { client } from "@/lib/client";
import { AllowedIP } from "@/gen/northstar_pb";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { AddAllowedIPModal } from "@/components/AddAllowedIPModal";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EditableField } from "@/components/EditableField";
import { toast } from "sonner";

export function AllowedIPsPage() {
  const [editingId, setEditingId] = useState<number | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["allowed_ips"],
    queryFn: async () => {
      const res = await client.listAllowedIPs({});
      return res.allowedIps;
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (payload: {
      id: number;
      cidr: string;
      description: string;
    }) => {
      await client.updateAllowedIP(payload);
    },
    onSuccess: () => {
      toast.success("Allowed IP updated");
      refetch();
    },
    onError: (err) => {
      toast.error("Failed to update allowed IP: " + (err as Error).message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      await client.deleteAllowedIP({ id });
    },
    onSuccess: () => {
      toast.success("Allowed IP deleted");
      refetch();
    },
    onError: (err) => {
      toast.error("Failed to delete allowed IP: " + (err as Error).message);
    },
  });

  const handleSave = (
    ip: AllowedIP,
    field: "cidr" | "description",
    value: string,
  ) => {
    updateMutation.mutate({
      id: ip.id,
      cidr: field === "cidr" ? value : ip.cidr,
      description: field === "description" ? value : ip.description,
    });
  };

  if (isLoading)
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground animate-pulse">
        <Logo className="w-8 h-8 animate-spin opacity-20" />
      </div>
    );

  if (error)
    return (
      <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
        Error loading allowed IPs: {error.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Access Control
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Manage whitelisted IP addresses and CIDR blocks allowed to access
            Northstar.
          </p>
        </div>
        <Button
          onClick={() => setIsAddModalOpen(true)}
          className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
        >
          <Plus className="w-4 h-4 mr-2" />
          Add Allowed IP
        </Button>
      </div>

      {data && data.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CIDR</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((ip) => (
              <TableRow key={ip.id}>
                <TableCell className="font-medium font-mono">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-primary/60" />
                    <EditableField
                      label="CIDR"
                      value={ip.cidr}
                      isEditing={editingId === ip.id}
                      setIsEditing={(editing) =>
                        setEditingId(editing ? ip.id : null)
                      }
                      onSave={(newValue) => handleSave(ip, "cidr", newValue)}
                      hideLabel
                    />
                  </div>
                </TableCell>
                <TableCell>
                  <EditableField
                    label="Description"
                    value={ip.description}
                    isEditing={editingId === ip.id}
                    setIsEditing={(editing) =>
                      setEditingId(editing ? ip.id : null)
                    }
                    onSave={(newValue) =>
                      handleSave(ip, "description", newValue)
                    }
                    hideLabel
                  />
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Delete Allowed IP</AlertDialogTitle>
                          <AlertDialogDescription>
                            Are you sure you want to delete {ip.cidr}? This
                            action cannot be undone. If you delete all IPs, you
                            might be locked out.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => deleteMutation.mutate(ip.id)}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                          >
                            Delete
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <Empty>
          <EmptyHeader>
            <EmptyMedia>
              <ShieldCheck className="w-12 h-12 text-muted-foreground/30" />
            </EmptyMedia>
            <EmptyTitle>No Allowed IPs</EmptyTitle>
            <EmptyDescription>
              Currently, there are no IP restrictions (or everyone is blocked
              depending on configuration). Add an IP to restrict access.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button onClick={() => setIsAddModalOpen(true)} variant="outline">
              <Plus className="w-4 h-4 mr-2" />
              Add First IP
            </Button>
          </EmptyContent>
        </Empty>
      )}

      {isAddModalOpen && (
        <AddAllowedIPModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
            setIsAddModalOpen(false);
            refetch();
          }}
        />
      )}
    </div>
  );
}
