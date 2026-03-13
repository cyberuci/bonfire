import { useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Field as UIField,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field";
import { Loader2, Upload } from "lucide-react";

interface FileUploadModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const fileUploadSchema = z.object({
  file: z.any().refine((f) => f !== null, "File is required"),
  description: z.string().optional(),
});

export function FileUploadModal({ onClose, onSuccess }: FileUploadModalProps) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (values: { file: File; description: string }) => {
      const formData = new FormData();
      formData.append("file", values.file);
      formData.append("description", values.description);

      const response = await fetch("/api/upload-file", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }
      return response.json();
    },
    onSuccess: () => {
      toast.success("File uploaded successfully");
      queryClient.invalidateQueries({ queryKey: ["files"] });
      onSuccess();
    },
    onError: (err) => {
      toast.error("Upload failed: " + (err as Error).message);
    },
  });

  const form = useForm({
    defaultValues: {
      file: null,
      description: "",
    } as z.input<typeof fileUploadSchema>,
    validators: {
      onChange: fileUploadSchema,
    },
    onSubmit: async ({ value }) => {
      if (!value.file) return;
      await mutation.mutateAsync({
        file: value.file,
        description: value.description ?? "",
      });
    },
  });

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[425px] bg-background border-border text-foreground">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold text-primary">
            Upload File
          </DialogTitle>
        </DialogHeader>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-4 pt-4"
        >
          <FieldGroup>
            <form.Field
              name="file"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <UIField data-invalid={isInvalid}>
                    <FieldLabel htmlFor="file-upload">Binary / Tool</FieldLabel>
                    <div className="flex items-center justify-center w-full">
                      <label
                        htmlFor="file-upload"
                        className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer bg-muted/20 border-border hover:bg-muted/30 transition-colors"
                      >
                        <div className="flex flex-col items-center justify-center pt-5 pb-6">
                          <Upload className="w-8 h-8 mb-4 text-muted-foreground" />
                          <p className="mb-2 text-sm text-muted-foreground">
                            <span className="font-semibold">
                              Click to upload
                            </span>{" "}
                            or drag and drop
                          </p>
                          <p className="text-xs text-muted-foreground/60">
                            {field.state.value
                              ? field.state.value.name
                              : "Maximum file size: 500MB"}
                          </p>
                        </div>
                        <input
                          id="file-upload"
                          type="file"
                          className="hidden"
                          onBlur={field.handleBlur}
                          onChange={(e) =>
                            field.handleChange(e.target.files?.[0] || null)
                          }
                        />
                      </label>
                    </div>
                    <FieldError errors={field.state.meta.errors} />
                  </UIField>
                );
              }}
            />

            <form.Field
              name="description"
              children={(field) => (
                <UIField>
                  <FieldLabel htmlFor={field.name}>Description</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    placeholder="e.g. Static nmap binary for Linux x64"
                    className="bg-background border-border focus-visible:ring-primary/50"
                  />
                  <FieldDescription>
                    Help the team understand what this file is for.
                  </FieldDescription>
                </UIField>
              )}
            />
          </FieldGroup>

          <DialogFooter className="pt-4 flex gap-2">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              className="flex-1 bg-muted hover:bg-muted/80 text-muted-foreground border-border hover:text-foreground"
            >
              Cancel
            </Button>
            <form.Subscribe
              selector={(state) => [state.canSubmit, state.isSubmitting]}
              children={([canSubmit, isSubmitting]) => (
                <Button
                  type="submit"
                  disabled={!canSubmit}
                  className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Uploading...
                    </>
                  ) : (
                    "Upload"
                  )}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
