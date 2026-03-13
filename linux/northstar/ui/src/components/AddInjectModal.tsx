import { useState, useRef, useEffect } from "react";
import { useForm } from "@tanstack/react-form";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { z } from "zod";
import { format } from "date-fns";
import { client } from "../lib/client";
import { Timestamp } from "@bufbuild/protobuf";
import { Check, ChevronDown, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldError,
  FieldDescription,
} from "@/components/ui/field";
const TEAM_MEMBERS = [
  "Eric",
  "Christopher",
  "Kristen",
  "Sienna",
  "Alex",
  "Adrian",
  "Athena",
  "Francis",
];

interface AddInjectModalProps {
  onClose: () => void;
  onSuccess: () => void;
}

const injectSchema = z.object({
  number: z.string().optional(),
  title: z.string().min(1, "Title is required"),
  description: z.string().optional(),
  dueTime: z.date({ message: "Due date is required" }),
  selectedAssignees: z.array(z.string()).optional(),
});

export function AddInjectModal({ onClose, onSuccess }: AddInjectModalProps) {
  const initialDue = new Date();
  const [dueTime, setDueTime] = useState(() => initialDue);
  const [dueDate, setDueDate] = useState(() => initialDue);
  const [isDuePickerOpen, setIsDuePickerOpen] = useState(false);
  const [selectedAssignees, setSelectedAssignees] = useState<string[]>([]);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setIsDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const mutation = useMutation({
    mutationFn: async (values: z.infer<typeof injectSchema>) => {
      const timestamp = Timestamp.fromDate(values.dueTime);

      return await client.addInject({
        title: values.title,
        number: values.number ?? "",
        description: values.description ?? "",
        due: timestamp,
        assigneeNames: values.selectedAssignees ?? [],
        content: "",
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
      number: "",
      title: "",
      description: "",
      dueTime: initialDue,
      selectedAssignees: [] as string[],
    } as z.input<typeof injectSchema>,
    validators: {
      onChange: injectSchema,
    },
    onSubmit: async ({ value }) => {
      await mutation.mutateAsync(value);
    },
  });

  const toggleAssignee = (name: string) => {
    setSelectedAssignees((prev) => {
      const next = prev.includes(name)
        ? prev.filter((n) => n !== name)
        : [...prev, name];
      form.setFieldValue("selectedAssignees", next);
      return next;
    });
  };

  const removeAssignee = (e: React.MouseEvent, name: string) => {
    e.stopPropagation();
    setSelectedAssignees((prev) => {
      const next = prev.filter((n) => n !== name);
      form.setFieldValue("selectedAssignees", next);
      return next;
    });
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="bg-background border-border text-foreground max-w-md">
        <DialogHeader>
          <DialogTitle className="text-xl font-bold text-primary">
            Add New Inject
          </DialogTitle>
        </DialogHeader>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            form.handleSubmit();
          }}
          className="space-y-4 py-4"
        >
          <FieldGroup>
            <div className="grid grid-cols-4 gap-4">
              <form.Field
                name="number"
                children={(field) => (
                  <Field className="col-span-1">
                    <FieldLabel htmlFor={field.name}>#</FieldLabel>
                    <Input
                      id={field.name}
                      name={field.name}
                      placeholder="01"
                      value={field.state.value}
                      onBlur={field.handleBlur}
                      onChange={(e) => field.handleChange(e.target.value)}
                      className="bg-background border-border focus:border-primary"
                    />
                  </Field>
                )}
              />
              <form.Field
                name="title"
                children={(field) => {
                  const isInvalid =
                    field.state.meta.isTouched && !field.state.meta.isValid;
                  return (
                    <Field data-invalid={isInvalid} className="col-span-3">
                      <FieldLabel htmlFor={field.name}>Title</FieldLabel>
                      <Input
                        id={field.name}
                        name={field.name}
                        placeholder="Initial Report"
                        value={field.state.value}
                        onBlur={field.handleBlur}
                        onChange={(e) => field.handleChange(e.target.value)}
                        className="bg-background border-border focus:border-primary"
                      />
                      <FieldError errors={field.state.meta.errors} />
                    </Field>
                  );
                }}
              />
            </div>

            <form.Field
              name="description"
              children={(field) => (
                <Field>
                  <FieldLabel htmlFor={field.name}>Description</FieldLabel>
                  <Input
                    id={field.name}
                    name={field.name}
                    placeholder="Submit the initial status report"
                    value={field.state.value}
                    onBlur={field.handleBlur}
                    onChange={(e) => field.handleChange(e.target.value)}
                    className="bg-background border-border focus:border-primary"
                  />
                </Field>
              )}
            />

            <form.Field
              name="dueTime"
              children={(field) => {
                const isInvalid =
                  field.state.meta.isTouched && !field.state.meta.isValid;
                return (
                  <FieldGroup className="gap-3">
                    <Field data-invalid={isInvalid}>
                      <FieldLabel htmlFor={field.name}>Due Date</FieldLabel>
                      <Popover
                        open={isDuePickerOpen}
                        onOpenChange={setIsDuePickerOpen}
                      >
                        <PopoverTrigger asChild>
                          <Button
                            variant="outline"
                            id={field.name}
                            className="w-auto justify-between font-normal"
                          >
                            <span className="flex-1 text-center">
                              {dueDate ? format(dueDate, "PPP") : "Select date"}
                            </span>
                            <ChevronDown className="ml-2 h-4 w-4" />
                          </Button>
                        </PopoverTrigger>
                        <PopoverContent
                          className="w-auto overflow-hidden p-0"
                          align="start"
                        >
                          <Calendar
                            mode="single"
                            selected={dueDate}
                            captionLayout="dropdown"
                            defaultMonth={dueDate}
                            onSelect={(date) => {
                              if (!date) return;
                              setDueDate(date);
                              const merged = new Date(date);
                              merged.setHours(dueTime.getHours());
                              merged.setMinutes(dueTime.getMinutes());
                              merged.setSeconds(0);
                              merged.setMilliseconds(0);
                              field.handleChange(merged);
                              setIsDuePickerOpen(false);
                            }}
                          />
                        </PopoverContent>
                      </Popover>
                      <FieldError errors={field.state.meta.errors} />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor={`${field.name}-time`}>
                        Time
                      </FieldLabel>
                      <Input
                        id={`${field.name}-time`}
                        type="time"
                        value={dueTime.toTimeString().slice(0, 5)}
                        onBlur={field.handleBlur}
                        onChange={(e) => {
                          const [hours, minutes] = e.target.value
                            .split(":")
                            .map((val) => parseInt(val, 10));
                          const nextTime = new Date(dueTime);
                          nextTime.setHours(hours || 0);
                          nextTime.setMinutes(minutes || 0);
                          nextTime.setSeconds(0);
                          nextTime.setMilliseconds(0);
                          setDueTime(nextTime);
                          const merged = new Date(dueDate);
                          merged.setHours(nextTime.getHours());
                          merged.setMinutes(nextTime.getMinutes());
                          merged.setSeconds(0);
                          merged.setMilliseconds(0);
                          field.handleChange(merged);
                        }}
                        className="bg-background appearance-none border-border focus:border-primary text-foreground [&::-webkit-calendar-picker-indicator]:hidden [&::-webkit-calendar-picker-indicator]:appearance-none"
                      />
                    </Field>
                  </FieldGroup>
                );
              }}
            />

            <form.Field
              name="selectedAssignees"
              children={(field) => (
                <Field ref={dropdownRef}>
                  <FieldLabel htmlFor={field.name}>Assignees</FieldLabel>
                  <div className="relative">
                    <div
                      className="min-h-[40px] w-full rounded-md border border-border bg-background px-3 py-2 text-sm ring-offset-background focus-within:ring-2 focus-within:ring-ring focus-within:ring-offset-2 cursor-pointer flex flex-wrap gap-1.5 items-center transition-all"
                      onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                    >
                      {selectedAssignees.length === 0 && (
                        <span className="text-muted-foreground">
                          Select team members...
                        </span>
                      )}
                      {selectedAssignees.map((name) => (
                        <span
                          key={name}
                          className="flex items-center gap-1 bg-muted text-foreground px-1.5 py-0.5 rounded text-xs border border-border"
                        >
                          {name}
                          <div
                            role="button"
                            onClick={(e) => removeAssignee(e, name)}
                            className="hover:text-destructive cursor-pointer p-0.5 rounded hover:bg-muted/80"
                          >
                            <X className="w-3 h-3" />
                          </div>
                        </span>
                      ))}
                      <div className="ml-auto">
                        <ChevronDown
                          className={cn(
                            "w-4 h-4 text-muted-foreground transition-transform",
                            isDropdownOpen && "rotate-180",
                          )}
                        />
                      </div>
                    </div>

                    {isDropdownOpen && (
                      <div className="absolute z-50 w-full mt-1 bg-popover border border-border rounded-md shadow-xl max-h-48 overflow-y-auto">
                        {TEAM_MEMBERS.map((name) => (
                          <div
                            key={name}
                            className={cn(
                              "flex items-center justify-between px-3 py-2 text-sm cursor-pointer hover:bg-muted transition-colors",
                              selectedAssignees.includes(name)
                                ? "text-primary bg-muted/50"
                                : "text-muted-foreground",
                            )}
                            onClick={() => toggleAssignee(name)}
                          >
                            {name}
                            {selectedAssignees.includes(name) && (
                              <Check className="w-4 h-4" />
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  {field.state.meta.errors.length > 0 && (
                    <FieldError errors={field.state.meta.errors} />
                  )}
                  <FieldDescription>
                    Assign team members responsible for this inject
                  </FieldDescription>
                </Field>
              )}
            />
          </FieldGroup>
          <DialogFooter className="gap-2 pt-4">
            <Button
              variant="ghost"
              onClick={onClose}
              type="button"
              className="text-muted-foreground hover:text-foreground hover:bg-muted"
            >
              Cancel
            </Button>
            <form.Subscribe
              selector={(state) => [state.canSubmit, state.isSubmitting]}
              children={([canSubmit, isSubmitting]) => (
                <Button
                  type="submit"
                  disabled={!canSubmit}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold"
                >
                  {isSubmitting ? "Adding..." : "Add Inject"}
                </Button>
              )}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
