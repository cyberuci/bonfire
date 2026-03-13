import { useForm } from "@tanstack/react-form";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { client } from "@/lib/client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { SearchableSelect } from "@/components/ui/searchable-select";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldError,
} from "@/components/ui/field";

interface AddWebsiteModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const websiteSchema = z.object({
  name: z.string().min(1, "Name is required"),
  url: z.string().min(1, "URL is required"),
  username: z.string().optional(),
  passwordIndex: z.string().optional(),
  oldPassword: z.string().optional(),
  serviceId: z.string().optional(),
});

export function AddWebsiteModal({ onClose, onSuccess }: AddWebsiteModalProps) {
  const queryClient = useQueryClient();

  const { data: services } = useQuery({
    queryKey: ["services"],
    queryFn: async () => {
      const response = await client.listServices({});
      return response.services;
    },
  });

  const mutation = useMutation({
    mutationFn: async (values: z.infer<typeof websiteSchema>) => {
      await client.addWebsite({
        name: values.name,
        url: values.url,
        username: values.username ?? "",
        passwordIndex:
          values.passwordIndex && values.passwordIndex !== "none"
            ? parseInt(values.passwordIndex)
            : undefined,
        oldPassword: values.oldPassword ?? "",
        serviceId: parseInt(values.serviceId ?? "0"),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["websites"] });
      onSuccess();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const form = useForm({
    defaultValues: {
      name: "",
      url: "",
      username: "",
      passwordIndex: "",
      oldPassword: "",
      serviceId: "0",
    } as z.input<typeof websiteSchema>,
    validators: {
      onChange: websiteSchema,
    },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value);
    },
  });

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[500px] bg-background border-border text-foreground">
        <DialogHeader>
          <DialogTitle className="text-primary">Add New Website</DialogTitle>
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
              name="name"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>Name</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      className="bg-background border-border text-foreground"
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="url"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>URL</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      className="bg-background border-border text-foreground"
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="username"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Username</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    className="bg-background border-border text-foreground"
                  />
                </Field>
              )}
            />

            <form.Field
              name="passwordIndex"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Password Index</FieldLabel>
                  <SearchableSelect
                    value={field.state.value || ""}
                    onValueChange={(value) => field.handleChange(value)}
                    options={[
                      { value: "none", label: "None" },
                      ...Array.from({ length: 90 }, (_, i) => ({
                        value: String(i),
                        label: String(i),
                      })),
                    ]}
                    placeholder="None"
                    id={field.name}
                    onBlur={field.handleBlur}
                  />
                </Field>
              )}
            />

            <form.Field
              name="oldPassword"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Default Password</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    type="password"
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    className="bg-background border-border text-foreground"
                  />
                </Field>
              )}
            />

            <form.Field
              name="serviceId"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Service</FieldLabel>
                  <SearchableSelect
                    value={field.state.value ?? "0"}
                    onValueChange={(value) => field.handleChange(value)}
                    options={[
                      { value: "0", label: "None" },
                      ...(services?.map((service) => ({
                        value: service.id.toString(),
                        label: `${service.name} (${service.technology})`,
                      })) ?? []),
                    ]}
                    placeholder="Select a service"
                    id={field.name}
                    onBlur={field.handleBlur}
                  />
                </Field>
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
                  className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground font-bold"
                  disabled={!canSubmit}
                >
                  {isSubmitting ? "Adding..." : "Add Website"}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
