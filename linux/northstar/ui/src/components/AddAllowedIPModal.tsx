import { useForm } from "@tanstack/react-form";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { client } from "../lib/client";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
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

interface AddAllowedIPModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const allowedIPSchema = z.object({
  cidr: z.string().min(1, "CIDR is required"),
  description: z.string().optional(),
});

export function AddAllowedIPModal({
  onClose,
  onSuccess,
}: AddAllowedIPModalProps) {
  const mutation = useMutation({
    mutationFn: async (values: z.infer<typeof allowedIPSchema>) => {
      await client.addAllowedIP({
        cidr: values.cidr,
        description: values.description || "",
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
      cidr: "",
      description: "",
    } as z.input<typeof allowedIPSchema>,
    validators: {
      onChange: allowedIPSchema,
    },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value);
    },
  });

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Add Allowed IP</DialogTitle>
        </DialogHeader>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-6"
        >
          <div className="space-y-4">
            <form.Field
              name="cidr"
              children={(field) => (
                <FieldGroup>
                  <FieldLabel htmlFor={field.name}>
                    CIDR / IP Address
                  </FieldLabel>
                  <Field>
                    <Input
                      id={field.name}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="e.g. 192.168.1.100/32"
                      className="font-mono"
                      autoFocus
                    />
                  </Field>
                  <FieldDescription>
                    Enter a single IP (e.g. 192.168.1.100/32) or a CIDR block
                    (e.g. 10.0.0.0/8). IPv6 is also supported.
                  </FieldDescription>
                  <FieldError errors={field.state.meta.errors} />
                </FieldGroup>
              )}
            />

            <form.Field
              name="description"
              children={(field) => (
                <FieldGroup>
                  <FieldLabel htmlFor={field.name}>Description</FieldLabel>
                  <Field>
                    <Input
                      id={field.name}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      placeholder="e.g. Admin VPN"
                    />
                  </Field>
                  <FieldError errors={field.state.meta.errors} />
                </FieldGroup>
              )}
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={mutation.isPending}
            >
              Cancel
            </Button>
            <form.Subscribe
              selector={(state) => [state.canSubmit, state.isSubmitting]}
              children={([canSubmit, isSubmitting]) => (
                <Button type="submit" disabled={!canSubmit || isSubmitting}>
                  {isSubmitting ? "Adding..." : "Add IP"}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
