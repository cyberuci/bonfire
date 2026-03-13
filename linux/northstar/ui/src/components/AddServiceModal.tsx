import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { client } from "../lib/client";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { SearchableSelect } from "@/components/ui/searchable-select";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldError,
  FieldDescription,
} from "@/components/ui/field";

interface AddServiceModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const serviceSchema = z.object({
  hostId: z.string().min(1, "Target host is required"),
  name: z.string().min(1, "Service name is required"),
  technology: z.string().optional(),
  scored: z.boolean().optional(),
  ports: z.string().optional(),
  passwordIndex: z.string().optional(),
});

export function AddServiceModal({ onClose, onSuccess }: AddServiceModalProps) {
  const queryClient = useQueryClient();

  const { data: hosts } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => {
      const res = await client.listHosts({});
      return res.hosts;
    },
  });

  const mutation = useMutation({
    mutationFn: async (values: z.infer<typeof serviceSchema>) => {
      const servicePorts = values.ports
        ? values.ports
            .split(",")
            .map((p) => p.trim())
            .filter((p) => p)
            .map((p) => {
              const port = parseInt(p);
              if (isNaN(port)) throw new Error(`Invalid port: ${p}`);
              return port;
            })
        : [];

      await client.addService({
        hostId: parseInt(values.hostId),
        name: values.name,
        technology: values.technology ?? "",
        scored: values.scored ?? false,
        ports: servicePorts,
        passwordIndex:
          values.passwordIndex && values.passwordIndex !== "none"
            ? parseInt(values.passwordIndex)
            : undefined,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      onSuccess();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const form = useForm({
    defaultValues: {
      hostId: "",
      name: "",
      technology: "",
      scored: false,
      ports: "",
      passwordIndex: "none",
    } as z.input<typeof serviceSchema>,
    validators: {
      onChange: serviceSchema,
    },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value);
    },
  });

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[425px] bg-background border-border text-foreground">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold text-primary">
            Add New Service
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
              name="hostId"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>Target Host</FieldLabel>
                    <SearchableSelect
                      value={field.state.value}
                      onValueChange={(value) => field.handleChange(value)}
                      options={
                        hosts?.map((host) => ({
                          value: host.id.toString(),
                          label: `${host.hostname} (${host.ip})`,
                        })) ?? []
                      }
                      placeholder="Select a host..."
                      id={field.name}
                      onBlur={field.handleBlur}
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="name"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>Service Name</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="e.g. Web Server, Database"
                      className="bg-background border-border focus-visible:ring-primary/50"
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="technology"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Technology</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    placeholder="e.g. Apache, PostgreSQL, Redis"
                    className="bg-background border-border focus-visible:ring-primary/50"
                  />
                </Field>
              )}
            />

            <form.Field
              name="ports"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Ports</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    placeholder="80, 443"
                    className="bg-background border-border focus-visible:ring-primary/50"
                  />
                  <FieldDescription>
                    Comma separated list of service ports
                  </FieldDescription>
                </Field>
              )}
            />

            <form.Field
              name="passwordIndex"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Password</FieldLabel>
                  <SearchableSelect
                    value={field.state.value ?? "none"}
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
                  />
                </Field>
              )}
            />

            <form.Field
              name="scored"
              children={(field) => (
                <Field>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border">
                    <div className="space-y-0.5">
                      <FieldLabel htmlFor={field.name}>
                        Scored Service
                      </FieldLabel>
                      <FieldDescription>
                        Enable if this service is tracked by the scoring engine
                      </FieldDescription>
                    </div>
                    <Switch
                      id={field.name}
                      checked={field.state.value}
                      onCheckedChange={(value) => field.handleChange(value)}
                    />
                  </div>
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
                  disabled={!canSubmit}
                  className="flex-1 bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
                >
                  {isSubmitting ? "Adding..." : "Add Service"}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
