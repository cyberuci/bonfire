import { useState, useRef, useEffect } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";
import { format } from "date-fns";
import { toast } from "sonner";
import { client } from "../lib/client";
import { Inject } from "../gen/northstar_pb.ts";
import { Timestamp } from "@bufbuild/protobuf";
import {
  ClipboardList,
  Image as ImageIcon,
  ExternalLink,
  Eye,
  PenLine,
  Users,
  Clock,
  Link as LinkIcon,
  CheckCircle2,
  Circle,
  Trash2,
  Edit2,
  Save,
  X,
  ChevronDown,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn, ensureAbsoluteUrl } from "@/lib/utils";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { DetailTile } from "./DetailTile";
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

interface InjectDetailModalProps {
  inject: Inject;
  onClose: () => void;
  onSuccess: () => void; // Kept for API consistency, though invalidation handles it
}

export function InjectDetailModal({ inject, onClose }: InjectDetailModalProps) {
  const [content, setContent] = useState(inject.content);
  const [completed, setCompleted] = useState(inject.completed);
  const [viewMode, setViewMode] = useState<"write" | "preview">("write");
  const [isUploading, setIsUploading] = useState(false);
  const [isEditing, setIsEditing] = useState(false);

  // Form State
  const [editTitle, setEditTitle] = useState(inject.title);
  const [editNumber, setEditNumber] = useState(inject.number);
  const [editDescription, setEditDescription] = useState(inject.description);
  const [editSubmissionUrl, setEditSubmissionUrl] = useState(
    inject.submissionUrl,
  );
  const [editDueDate, setEditDueDate] = useState<Date | undefined>(() =>
    inject.due ? inject.due.toDate() : undefined,
  );
  const [editDueTime, setEditDueTime] = useState(() =>
    inject.due ? inject.due.toDate() : new Date(),
  );
  const [isDuePickerOpen, setIsDuePickerOpen] = useState(false);
  const [editAssignees, setEditAssignees] = useState<string[]>(
    inject.assignees.map((a) => a.name),
  );

  const fileInputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();

  // Always sync content from server (live updates from other clients).
  // This ensures stale local state never overwrites newer server state on blur.
  useEffect(() => {
    setContent(inject.content);
  }, [inject.content]);

  useEffect(() => {
    setCompleted(inject.completed);
  }, [inject.completed]);

  // Sync state when entering edit mode
  useEffect(() => {
    if (isEditing) {
      setEditTitle(inject.title);
      setEditNumber(inject.number);
      setEditDescription(inject.description);
      setEditSubmissionUrl(inject.submissionUrl);
      setEditAssignees(inject.assignees.map((a) => a.name));
      if (inject.due) {
        const date = inject.due.toDate();
        setEditDueDate(date);
        setEditDueTime(date);
      } else {
        setEditDueDate(undefined);
        setEditDueTime(new Date());
      }
    }
  }, [isEditing, inject]);

  const mutation = useMutation({
    mutationFn: async (
      updatedInject: Partial<Inject> & {
        id: number;
        assigneeNames?: string[];
        submissionUrl?: string;
      },
    ) => {
      return await client.updateInject({
        id: updatedInject.id,
        number: updatedInject.number ?? inject.number,
        title: updatedInject.title ?? inject.title,
        description: updatedInject.description ?? inject.description,
        due: updatedInject.due ?? inject.due,
        content: updatedInject.content ?? content,
        completed: updatedInject.completed ?? completed,
        submissionUrl: updatedInject.submissionUrl ?? inject.submissionUrl,
        assigneeNames: updatedInject.assigneeNames,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["injects"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      return await client.deleteInject({ id: inject.id });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["injects"] });
      toast.success("Inject deleted successfully");
      onClose();
    },
    onError: (err) => {
      toast.error(`Failed to delete inject: ${err.message}`);
    },
  });

  // Auto-save handler for content/status (non-edit mode)
  const handleUpdate = (updates: Partial<Inject>) => {
    if (updates.content !== undefined) setContent(updates.content);
    if (updates.completed !== undefined) setCompleted(updates.completed);
    mutation.mutate({ id: inject.id, ...updates });
  };

  const handleSaveChanges = () => {
    const updates: any = {
      title: editTitle,
      number: editNumber,
      description: editDescription,
      submissionUrl: editSubmissionUrl,
      assigneeNames: editAssignees,
    };

    if (editDueDate) {
      const date = new Date(editDueDate);
      date.setHours(editDueTime.getHours());
      date.setMinutes(editDueTime.getMinutes());
      date.setSeconds(0);
      date.setMilliseconds(0);
      updates.due = Timestamp.fromDate(date);
    }

    mutation.mutate({ id: inject.id, ...updates });
    setIsEditing(false);
    toast.success("Inject details updated");
  };

  const toggleAssignee = (name: string) => {
    setEditAssignees((prev) =>
      prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name],
    );
  };

  const removeAssignee = (e: React.MouseEvent, name: string) => {
    e.stopPropagation();
    setEditAssignees((prev) => prev.filter((n) => n !== name));
  };

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();

      const imageMarkdown = `\n![Screenshot](${data.url})`;
      const newContent = content + imageMarkdown;

      setContent(newContent);
      setViewMode("write");

      // Auto-save the new content with image
      handleUpdate({ content: newContent });
    } catch (error) {
      console.error("Upload failed:", error);
      alert("Failed to upload image");
    } finally {
      setIsUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-[95vw] sm:max-w-7xl h-[85vh] bg-background border-border text-foreground shadow-2xl shadow-black p-0 overflow-hidden flex flex-col">
        {/* Header */}
        <DialogHeader className="border-b border-border px-6 py-4 bg-muted/40 flex-row items-center justify-between space-y-0">
          <div className="flex items-center gap-4">
            <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
              <ClipboardList className="w-5 h-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-muted-foreground uppercase tracking-widest leading-none">
                  Inject Details
                </span>
                <span className="text-xl font-black font-mono text-primary">
                  #{inject.number}
                </span>
              </div>
              <DialogTitle className="text-xl text-foreground mt-1">
                {inject.title}
              </DialogTitle>
            </div>
          </div>

          <div className="flex items-center gap-2 mr-6">
            {!isEditing && (
              <>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete Inject?</AlertDialogTitle>
                      <AlertDialogDescription>
                        This action cannot be undone. This inject and all its
                        content will be permanently removed.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction
                        onClick={() => deleteMutation.mutate()}
                        className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                      >
                        Delete Inject
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>

                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-muted-foreground hover:text-primary hover:bg-primary/10"
                  onClick={() => setIsEditing(true)}
                >
                  <Edit2 className="w-4 h-4" />
                </Button>

                <Badge
                  variant="outline"
                  onClick={() => handleUpdate({ completed: !completed })}
                  className={cn(
                    "cursor-pointer flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2 select-none",
                    completed
                      ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
                      : "bg-warning/20 text-warning border-warning/50 hover:bg-warning/10",
                  )}
                >
                  {completed ? (
                    <CheckCircle2 className="w-3 h-3" />
                  ) : (
                    <Circle className="w-3 h-3" />
                  )}
                  {completed ? "Completed" : "In Progress"}
                </Badge>
              </>
            )}
            {isEditing && (
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setIsEditing(false)}
                >
                  Cancel
                </Button>
                <Button size="sm" onClick={handleSaveChanges} className="gap-2">
                  <Save className="w-4 h-4" /> Save
                </Button>
              </div>
            )}
          </div>
        </DialogHeader>

        {/* Content Grid */}
        <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 overflow-hidden">
          {/* Main Column: Markdown Editor (Spans 2 columns) */}
          <div className="lg:col-span-2 flex flex-col h-full overflow-hidden">
            <DetailTile
              title="Inject Content & Evidence"
              icon={PenLine}
              className="h-full flex flex-col"
              noPadding
            >
              <div className="flex-none p-2 border-b border-border flex items-center justify-between bg-muted/30">
                <div className="flex space-x-1 bg-background rounded-md p-0.5 border border-border">
                  <button
                    onClick={() => setViewMode("write")}
                    className={cn(
                      "px-3 py-1 text-[10px] font-bold uppercase rounded-sm transition-all flex items-center gap-1.5",
                      viewMode === "write"
                        ? "bg-muted text-primary shadow-sm"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <PenLine className="w-3 h-3" /> Write
                  </button>
                  <button
                    onClick={() => setViewMode("preview")}
                    className={cn(
                      "px-3 py-1 text-[10px] font-bold uppercase rounded-sm transition-all flex items-center gap-1.5",
                      viewMode === "preview"
                        ? "bg-muted text-primary shadow-sm"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <Eye className="w-3 h-3" /> Preview
                  </button>
                </div>

                <div className="flex items-center gap-1">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleUpload}
                    className="hidden"
                    accept="image/*"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-[10px] font-bold uppercase text-muted-foreground hover:text-primary hover:bg-muted"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={isUploading}
                  >
                    <ImageIcon className="w-3 h-3 mr-1.5" />
                    {isUploading ? "Uploading..." : "Attach Image"}
                  </Button>
                </div>
              </div>

              <div className="flex-1 relative overflow-hidden bg-background/30">
                {viewMode === "write" ? (
                  <textarea
                    value={content}
                    onChange={(e) => setContent(e.target.value)}
                    onBlur={(e) => {
                      if (e.target.value !== inject.content) {
                        handleUpdate({ content: e.target.value });
                      }
                    }}
                    placeholder="Describe the inject resolution, paste logs, or attach screenshots..."
                    className="w-full h-full bg-transparent p-6 text-muted-foreground font-mono text-sm resize-none focus:outline-none placeholder:text-muted-foreground/50 leading-relaxed custom-scrollbar"
                  />
                ) : (
                  <ScrollArea className="h-full w-full">
                    <div className="p-8 prose prose-invert prose-sm max-w-none text-muted-foreground prose-p:text-muted-foreground prose-li:text-muted-foreground prose-headings:text-foreground prose-a:text-info prose-strong:text-foreground prose-code:text-primary prose-code:bg-muted prose-pre:bg-muted prose-pre:border prose-pre:border-border">
                      <ReactMarkdown
                        remarkPlugins={[remarkBreaks, remarkGfm]}
                        components={{
                          img: ({ node, ...props }) => (
                            <img
                              {...props}
                              className="rounded-lg border border-border shadow-lg max-w-full h-auto my-4"
                            />
                          ),
                          a: ({ node, ...props }) => (
                            <a
                              {...props}
                              className="text-info hover:underline"
                              target="_blank"
                              rel="noopener noreferrer"
                            />
                          ),
                        }}
                      >
                        {content || "*No content provided.*"}
                      </ReactMarkdown>
                    </div>
                  </ScrollArea>
                )}
              </div>
            </DetailTile>
          </div>

          {/* Right Column: Meta Info */}
          <div className="space-y-6 overflow-y-auto custom-scrollbar lg:h-full">
            {isEditing ? (
              <DetailTile title="Edit Details" icon={Edit2}>
                <div className="space-y-3">
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-xs">
                      Number
                    </Label>
                    <Input
                      value={editNumber}
                      onChange={(e) => setEditNumber(e.target.value)}
                      className="bg-background border-border"
                    />
                  </div>
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-xs">
                      Title
                    </Label>
                    <Input
                      value={editTitle}
                      onChange={(e) => setEditTitle(e.target.value)}
                      className="bg-background border-border"
                    />
                  </div>
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-xs">
                      Description
                    </Label>
                    <Input
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      className="bg-background border-border"
                    />
                  </div>
                  <FieldGroup className="gap-3">
                    <Field>
                      <FieldLabel className="text-muted-foreground text-xs">
                        Due Date
                      </FieldLabel>
                      <Popover
                        open={isDuePickerOpen}
                        onOpenChange={setIsDuePickerOpen}
                      >
                        <PopoverTrigger asChild>
                          <Button
                            variant="outline"
                            className="w-40 justify-between font-normal"
                          >
                            <span className="flex-1 text-center">
                              {editDueDate
                                ? format(editDueDate, "PPP")
                                : "Select date"}
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
                            selected={editDueDate}
                            captionLayout="dropdown"
                            defaultMonth={editDueDate}
                            onSelect={(date) => {
                              if (!date) return;
                              setEditDueDate(date);
                              setIsDuePickerOpen(false);
                            }}
                          />
                        </PopoverContent>
                      </Popover>
                    </Field>
                    <Field>
                      <FieldLabel className="text-muted-foreground text-xs">
                        Time
                      </FieldLabel>
                      <Input
                        type="time"
                        value={editDueTime.toTimeString().slice(0, 5)}
                        onChange={(e) => {
                          const [hours, minutes] = e.target.value
                            .split(":")
                            .map((val) => parseInt(val, 10));
                          const nextTime = new Date(editDueTime);
                          nextTime.setHours(hours || 0);
                          nextTime.setMinutes(minutes || 0);
                          nextTime.setSeconds(0);
                          nextTime.setMilliseconds(0);
                          setEditDueTime(nextTime);
                        }}
                        className="bg-background appearance-none border-border text-foreground [&::-webkit-calendar-picker-indicator]:hidden [&::-webkit-calendar-picker-indicator]:appearance-none"
                      />
                    </Field>
                  </FieldGroup>
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-xs">
                      Submission URL
                    </Label>
                    <Input
                      value={editSubmissionUrl}
                      onChange={(e) => setEditSubmissionUrl(e.target.value)}
                      className="bg-background border-border"
                      placeholder="https://..."
                    />
                  </div>
                  <div className="space-y-3">
                    <Label className="text-muted-foreground text-xs">
                      Assignees
                    </Label>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <div className="min-h-[36px] w-full rounded-md border border-border bg-background px-3 py-2 text-sm cursor-pointer flex flex-wrap gap-1.5 items-center">
                          {editAssignees.length === 0 && (
                            <span className="text-muted-foreground text-xs">
                              Select...
                            </span>
                          )}
                          {editAssignees.map((name) => (
                            <span
                              key={name}
                              className="flex items-center gap-1 bg-muted text-foreground px-1.5 py-0.5 rounded text-[10px] border border-border"
                            >
                              {name}
                              <div
                                role="button"
                                onClick={(e) => removeAssignee(e, name)}
                                className="hover:text-destructive p-0.5 rounded hover:bg-muted/80"
                              >
                                <X className="w-2.5 h-2.5" />
                              </div>
                            </span>
                          ))}
                          <ChevronDown className="ml-auto w-3 h-3 text-muted-foreground" />
                        </div>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent className="w-56" align="start">
                        {TEAM_MEMBERS.map((name) => (
                          <DropdownMenuCheckboxItem
                            key={name}
                            checked={editAssignees.includes(name)}
                            onCheckedChange={() => toggleAssignee(name)}
                            onSelect={(e) => e.preventDefault()}
                          >
                            {name}
                          </DropdownMenuCheckboxItem>
                        ))}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              </DetailTile>
            ) : (
              <>
                <DetailTile title="Status & Deadline" icon={Clock}>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center pb-3 border-b border-border/50">
                      <span className="text-muted-foreground text-[11px] font-medium uppercase">
                        Due Time
                      </span>
                      <span className="text-foreground font-mono text-xs">
                        {inject.due?.toDate().toLocaleString()}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground text-[11px] font-medium uppercase">
                        Status
                      </span>
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[9px] font-black uppercase tracking-widest px-2 py-0.5 border",
                          completed
                            ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
                            : "bg-warning/20 text-warning border-warning/50 hover:bg-warning/10",
                        )}
                      >
                        {completed ? "Completed" : "Pending"}
                      </Badge>
                    </div>
                  </div>
                </DetailTile>

                <DetailTile title="Assignees" icon={Users}>
                  <div className="space-y-2">
                    {inject.assignees.length > 0 ? (
                      inject.assignees.map((a) => (
                        <div
                          key={a.id}
                          className="flex items-center gap-2 p-2 rounded bg-muted/50 border border-border/50"
                        >
                          <div className="w-6 h-6 rounded-full bg-muted border border-border flex items-center justify-center text-[10px] font-bold text-muted-foreground">
                            {a.name.charAt(0)}
                          </div>
                          <span className="text-xs font-medium text-muted-foreground">
                            {a.name}
                          </span>
                        </div>
                      ))
                    ) : (
                      <div className="text-muted-foreground text-[10px] italic text-center py-2">
                        No assignees
                      </div>
                    )}
                  </div>
                </DetailTile>

                <DetailTile title="Quick Actions" icon={LinkIcon}>
                  {inject.submissionUrl ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full justify-start text-xs border-border bg-background hover:bg-muted text-muted-foreground hover:text-foreground"
                      onClick={() =>
                        window.open(
                          ensureAbsoluteUrl(inject.submissionUrl),
                          "_blank",
                        )
                      }
                    >
                      <ExternalLink className="w-3 h-3 mr-2" />
                      View Submission Portal
                    </Button>
                  ) : (
                    <div className="text-muted-foreground text-[10px] italic text-center py-2">
                      No submission URL linked
                    </div>
                  )}
                </DetailTile>
              </>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
