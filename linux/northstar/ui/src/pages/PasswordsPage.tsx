import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  KeyRound,
  Trash2,
  ExternalLink,
  Server,
  Globe,
  Monitor,
  Sprout,
} from "lucide-react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { toast } from "sonner";
import { client } from "@/lib/client";
import { PasswordEntry } from "@/gen/northstar_pb";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EditableField } from "@/components/EditableField";
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
import { cn } from "@/lib/utils";

const PASSWORD_CATEGORIES = [
  { key: "linux", label: "Linux" },
  { key: "windows", label: "Windows" },
  { key: "misc", label: "Misc" },
];

const CATEGORY_KEYS = new Set(PASSWORD_CATEGORIES.map((item) => item.key));

const ASSIGNMENT_ICONS: Record<string, React.ElementType> = {
  host: Server,
  service: Monitor,
  website: Globe,
};

export function PasswordsPage() {
  const [editingIndex, setEditingIndex] = useState<number | null>(null);

  const navigate = useNavigate({ from: "/passwords" });
  const search = useSearch({ from: "/passwords" });
  const highlight = search.highlight;
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ["passwords"],
    queryFn: async () => {
      const res = await client.listPasswords({});
      return res.passwords;
    },
  });

  const activeCategory = useMemo(() => {
    if (search.category && CATEGORY_KEYS.has(search.category)) {
      return search.category;
    }
    if (highlight !== undefined && data) {
      const entry = data.find((d) => d.index === highlight);
      if (entry && entry.category && CATEGORY_KEYS.has(entry.category)) {
        return entry.category;
      }
    }
    return "linux";
  }, [search.category, highlight, data]);

  const grouped = useMemo(() => {
    const buckets: Record<string, PasswordEntry[]> = {
      linux: [],
      windows: [],
      misc: [],
    };
    (data ?? []).forEach((entry) => {
      const key = entry.category || "misc";
      if (buckets[key]) {
        buckets[key].push(entry);
      } else {
        buckets.misc.push(entry);
      }
    });
    return buckets;
  }, [data]);

  const hasPasswords = (data ?? []).length > 0;

  // Seed mutation
  const seedMutation = useMutation({
    mutationFn: async () => {
      return await client.seedPasswords({});
    },
    onSuccess: (res) => {
      toast.success(`Seeded ${res.count} password indices`);
      queryClient.invalidateQueries({ queryKey: ["passwords"] });
    },
    onError: (err) => {
      toast.error(`Seed failed: ${err.message}`);
    },
  });

  // Highlight effect
  useEffect(() => {
    if (highlight !== undefined && data) {
      setTimeout(() => {
        const el = document.getElementById(`password-row-${highlight}`);
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
          el.classList.add(
            "bg-primary/20",
            "transition-colors",
            "duration-1000",
          );
          setTimeout(() => el.classList.remove("bg-primary/20"), 2000);
        }
      }, 100);
    }
  }, [highlight, data]);

  // Update comment mutation
  const commentMutation = useMutation({
    mutationFn: async (args: { index: number; comment: string }) => {
      return await client.updatePasswordComment({
        index: args.index,
        comment: args.comment,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["passwords"] });
    },
  });

  // Clear mutation
  const clearMutation = useMutation({
    mutationFn: async () => {
      return await client.clearPasswords({});
    },
    onSuccess: () => {
      toast.success("Password indices cleared");
      queryClient.invalidateQueries({ queryKey: ["passwords"] });
    },
    onError: (err) => {
      toast.error(`Clear failed: ${err.message}`);
    },
  });

  if (isLoading)
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground animate-pulse">
        <Logo className="w-8 h-8 animate-spin opacity-20" />
      </div>
    );

  if (error)
    return (
      <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
        Error loading passwords: {error.message}
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Password Index
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            {hasPasswords
              ? `${(data ?? []).length} password indices`
              : "Seed password indices to get started"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {hasPasswords && (
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
                  <AlertDialogTitle>
                    Clear All Password Indices?
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    This will delete all password indices and remove all
                    password assignments from hosts, services, and websites.
                    This action cannot be undone.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => clearMutation.mutate()}
                    className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                  >
                    Clear Everything
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
          {!hasPasswords && (
            <Button
              onClick={() => seedMutation.mutate()}
              disabled={seedMutation.isPending}
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20 gap-2"
            >
              <Sprout className="w-4 h-4" />
              {seedMutation.isPending ? "Seeding..." : "Seed Indices"}
            </Button>
          )}
        </div>
      </div>

      {/* Main Content */}
      {!hasPasswords ? (
        <Empty className="bg-muted/20">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <KeyRound className="h-6 w-6" />
            </EmptyMedia>
            <EmptyTitle>No password indices</EmptyTitle>
            <EmptyDescription>
              Seed password indices (0-89) to start linking passwords to hosts,
              services, and websites. No actual passwords are stored here — use
              your physical password sheet for the real values.
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button
              onClick={() => seedMutation.mutate()}
              disabled={seedMutation.isPending}
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20 gap-2"
            >
              <Sprout className="w-4 h-4" />
              {seedMutation.isPending ? "Seeding..." : "Seed Indices (0-89)"}
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <Tabs
          value={activeCategory}
          onValueChange={(value) =>
            navigate({ search: (prev) => ({ ...prev, category: value }) })
          }
          className="space-y-4"
        >
          <TabsList className="bg-muted/50 border border-border">
            {PASSWORD_CATEGORIES.map((category) => (
              <TabsTrigger key={category.key} value={category.key}>
                {category.label}
                <span className="ml-2 text-[10px] font-bold text-muted-foreground">
                  {grouped[category.key]?.length ?? 0}
                </span>
              </TabsTrigger>
            ))}
          </TabsList>

          {PASSWORD_CATEGORIES.map((category) => (
            <TabsContent key={category.key} value={category.key}>
              {grouped[category.key]?.length ? (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[70px]">#</TableHead>
                      <TableHead>Assigned To</TableHead>
                      <TableHead>Notes</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {grouped[category.key].map((entry) => (
                      <TableRow
                        key={entry.index}
                        id={`password-row-${entry.index}`}
                      >
                        <TableCell className="font-mono text-xs font-bold text-primary">
                          {entry.index}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {entry.assignments.length > 0 ? (
                              entry.assignments.map((a, i) => {
                                const Icon = ASSIGNMENT_ICONS[a.type] || Server;
                                return (
                                  <Badge
                                    key={`${a.type}-${a.entityId}-${i}`}
                                    variant="outline"
                                    className={cn(
                                      "text-[10px] font-medium gap-1 cursor-pointer hover:bg-muted/80 transition-colors",
                                      a.type === "host" &&
                                        "border-info/30 text-info",
                                      a.type === "service" &&
                                        "border-warning/30 text-warning",
                                      a.type === "website" &&
                                        "border-success/30 text-success",
                                    )}
                                    onClick={() => {
                                      if (a.type === "host")
                                        navigate({
                                          to: "/",
                                          search: {
                                            hostId: a.entityId,
                                          },
                                        } as any);
                                      else if (a.type === "service")
                                        navigate({
                                          to: "/services",
                                          search: {
                                            serviceId: a.entityId,
                                          },
                                        } as any);
                                      else if (a.type === "website")
                                        navigate({
                                          to: "/websites",
                                          search: {
                                            websiteId: a.entityId,
                                          },
                                        } as any);
                                    }}
                                  >
                                    <Icon className="w-3 h-3" />
                                    {a.label}
                                    <ExternalLink className="w-2.5 h-2.5 opacity-50" />
                                  </Badge>
                                );
                              })
                            ) : (
                              <span className="text-muted-foreground text-[10px] italic">
                                Unassigned
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          <div className="min-w-[200px]">
                            <EditableField
                              label="Notes"
                              value={entry.comment || ""}
                              isEditing={editingIndex === entry.index}
                              setIsEditing={(editing) =>
                                setEditingIndex(editing ? entry.index : null)
                              }
                              onSave={(value) =>
                                commentMutation.mutate({
                                  index: entry.index,
                                  comment: value,
                                })
                              }
                              hideLabel
                            />
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : (
                <div className="text-muted-foreground text-sm italic text-center py-8">
                  No {category.label.toLowerCase()} passwords in this range.
                </div>
              )}
            </TabsContent>
          ))}
        </Tabs>
      )}
    </div>
  );
}
