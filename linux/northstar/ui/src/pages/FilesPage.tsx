import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FolderOpen, Plus, Download, Link, Trash2 } from "lucide-react";
import { client } from "@/lib/client";
import { File } from "@/gen/northstar_pb";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
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
import { FileUploadModal } from "@/components/FileUploadModal";

const formatBytes = (bytes: number) => {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

export function FilesPage() {
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [editingFileId, setEditingFileId] = useState<number | null>(null);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["files"],
    queryFn: async () => {
      const res = await client.listFiles({});
      return res.files;
    },
  });

  const updateMutation = useMutation({
    mutationFn: async (payload: {
      id: number;
      name: string;
      description: string;
    }) => {
      await client.updateFile(payload);
    },
    onSuccess: () => {
      toast.success("File updated");
      refetch();
    },
    onError: (err) => {
      toast.error("Failed to update file: " + (err as Error).message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      await client.deleteFile({ id });
    },
    onSuccess: () => {
      toast.success("File deleted");
      refetch();
    },
    onError: (err) => {
      toast.error("Failed to delete file: " + (err as Error).message);
    },
  });

  const handleSave = (
    file: File,
    field: "name" | "description",
    value: string,
  ) => {
    updateMutation.mutate({
      id: file.id,
      name: field === "name" ? value : file.name,
      description: field === "description" ? value : file.description,
    });
  };

  const copyToClipboard = (url: string) => {
    const fullUrl = window.location.origin + url;
    navigator.clipboard.writeText(fullUrl);
    toast.success("Link copied to clipboard");
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
        Error loading files: {error.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Files
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Shared binaries, tools, and team resources
          </p>
        </div>
        <Button
          onClick={() => setIsUploadModalOpen(true)}
          className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
        >
          <Plus className="w-4 h-4 mr-2" />
          Upload File
        </Button>
      </div>

      {data && data.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>File Name</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Uploaded At</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((file) => (
              <TableRow key={file.id}>
                <TableCell className="font-medium">
                  <div className="flex items-center gap-2">
                    <FolderOpen className="w-4 h-4 text-primary/60" />
                    <EditableField
                      label="Name"
                      value={file.name}
                      isEditing={editingFileId === file.id}
                      setIsEditing={(editing) =>
                        setEditingFileId(editing ? file.id : null)
                      }
                      onSave={(newValue) => handleSave(file, "name", newValue)}
                      hideLabel
                    />
                  </div>
                </TableCell>
                <TableCell className="text-muted-foreground text-sm whitespace-nowrap">
                  {formatBytes(Number(file.size))}
                </TableCell>
                <TableCell>
                  <EditableField
                    label="Description"
                    value={file.description}
                    isEditing={editingFileId === file.id}
                    setIsEditing={(editing) =>
                      setEditingFileId(editing ? file.id : null)
                    }
                    onSave={(newValue) =>
                      handleSave(file, "description", newValue)
                    }
                    hideLabel
                  />
                </TableCell>
                <TableCell className="text-muted-foreground text-xs">
                  {file.uploadedAt?.toDate().toLocaleString()}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 hover:text-primary hover:bg-primary/10"
                      asChild
                    >
                      <a href={file.url} download={file.name}>
                        <Download className="h-4 w-4" />
                      </a>
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 hover:text-primary hover:bg-primary/10"
                      onClick={() => copyToClipboard(file.url)}
                    >
                      <Link className="h-4 w-4" />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 hover:text-destructive hover:bg-destructive/10"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>
                            Delete {file.name}?
                          </AlertDialogTitle>
                          <AlertDialogDescription>
                            This action cannot be undone. This will permanently
                            delete the file from storage.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Cancel</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => deleteMutation.mutate(file.id)}
                            className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                          >
                            Delete File
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
        <Empty className="bg-muted/20">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <FolderOpen className="h-6 w-6" />
            </EmptyMedia>
            <EmptyTitle>No files shared yet</EmptyTitle>
            <EmptyDescription>
              Upload binaries or tools for the team to access.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button
              onClick={() => setIsUploadModalOpen(true)}
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
            >
              <Plus className="w-4 h-4 mr-2" />
              Upload File
            </Button>
          </EmptyContent>
        </Empty>
      )}

      {isUploadModalOpen && (
        <FileUploadModal
          onClose={() => setIsUploadModalOpen(false)}
          onSuccess={() => {
            setIsUploadModalOpen(false);
            refetch();
          }}
        />
      )}
    </div>
  );
}
