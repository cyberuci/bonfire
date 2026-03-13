import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { client } from "../lib/client";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SearchableSelect } from "@/components/ui/searchable-select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldError,
  FieldDescription,
} from "@/components/ui/field";

interface AddHostModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const hostSchema = z.object({
  ip: z.string().min(1, "IP Address is required"),
  passwordIndex: z.string().optional(),
  osType: z.string().min(1, "OS Type is required"),
  hostname: z.string().optional(),
  ports: z.string().optional(),
  networkId: z.string().optional(),
});

export function AddHostModal({ onClose, onSuccess }: AddHostModalProps) {
  const { data: networks } = useQuery({
    queryKey: ["networks"],
    queryFn: async () => {
      const res = await client.listNetworks({});
      return res.networks;
    },
  });

  const mutation = useMutation({
    mutationFn: async (values: z.infer<typeof hostSchema>) => {
      const hostPorts = values.ports
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

      await client.addHost({
        ip: values.ip,
        passwordIndex: values.passwordIndex
          ? parseInt(values.passwordIndex)
          : undefined,
        hostname: values.hostname,
        osType: values.osType,
        firewallEnabled: false,
        ports: hostPorts,
        networkId:
          values.networkId && values.networkId !== "none"
            ? parseInt(values.networkId)
            : undefined,
      });
    },
    onSuccess: () => {
      onSuccess();
    },
    onError: (err) => {
      toast.error(err.message);
    },
  });

  const form = useForm({
    defaultValues: {
      ip: "",
      passwordIndex: "",
      osType: "Linux",
      hostname: "",
      ports: "",
      networkId: "",
    } as z.input<typeof hostSchema>,
    validators: {
      onChange: hostSchema,
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
            Add New Host
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
              name="ip"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>IP Address</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="192.168.1.10"
                      className="bg-background border-border focus-visible:ring-primary/50"
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="passwordIndex"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
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
                    <FieldDescription>
                      Reference a password from the vault
                    </FieldDescription>
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="osType"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>OS Type</FieldLabel>
                    <Select
                      value={field.state.value}
                      onValueChange={(value) => field.handleChange(value)}
                    >
                      <SelectTrigger className="bg-background border-border focus-visible:ring-primary/50">
                        <SelectValue placeholder="Select OS" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Linux">Linux</SelectItem>
                        <SelectItem value="Windows">Windows</SelectItem>
                        <SelectItem value="Unknown">Unknown</SelectItem>
                      </SelectContent>
                    </Select>
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="networkId"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Network</FieldLabel>
                  <SearchableSelect
                    value={field.state.value || "none"}
                    onValueChange={(value) => field.handleChange(value)}
                    options={[
                      { value: "none", label: "None" },
                      ...(networks?.map((n) => ({
                        value: n.id.toString(),
                        label: n.name,
                      })) ?? []),
                    ]}
                    placeholder="Select network"
                    id={field.name}
                    onBlur={field.handleBlur}
                  />
                </Field>
              )}
            />

            <form.Field
              name="hostname"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>Hostname</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="web-server-01"
                      className="bg-background border-border focus-visible:ring-primary/50"
                    />
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
            />

            <form.Field
              name="ports"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <Field data-invalid={isInvalid}>
                    <FieldLabel htmlFor={field.name}>Ports</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="80, 443, 22"
                      className="bg-background border-border focus-visible:ring-primary/50"
                    />
                    <FieldDescription>
                      Comma separated list of open ports
                    </FieldDescription>
                    <FieldError errors={field.state.meta.errors} />
                  </Field>
                );
              }}
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
                  {isSubmitting ? "Adding..." : "Add Host"}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
