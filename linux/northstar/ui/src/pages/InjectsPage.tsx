import { useMemo, useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { client } from "../lib/client";
import { Inject } from "../gen/northstar_pb.ts";
import {
  ArrowUpDown,
  CheckCircle2,
  Circle,
  ClipboardList,
  Clock,
  Plus,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { Button } from "@/components/ui/button";

import { Input } from "@/components/ui/input";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AddInjectModal } from "../components/AddInjectModal";
import { InjectDetailModal } from "../components/InjectDetailModal";
import { useNavigate, useSearch } from "@tanstack/react-router";

// ─── Countdown hook ──────────────────────────────────────────
function useCountdown(due: Date | undefined, completed: boolean) {
  const [timeLeft, setTimeLeft] = useState("");
  const [isUrgent, setIsUrgent] = useState(false);

  useEffect(() => {
    if (completed || !due) {
      setTimeLeft("");
      setIsUrgent(false);
      return;
    }

    const update = () => {
      const now = Date.now();
      const dueMs = due.getTime();
      const diff = dueMs - now;

      if (diff <= 0) {
        setTimeLeft("EXPIRED");
        setIsUrgent(true);
        return;
      }

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setIsUrgent(hours === 0 && minutes < 5);
      setTimeLeft(`${hours > 0 ? hours + "h " : ""}${minutes}m ${seconds}s`);
    };

    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [due, completed]);

  return { timeLeft, isUrgent };
}

// ─── Per-row component (needs its own hook call) ─────────────
function InjectRow({
  inject,
  onClick,
}: {
  inject: Inject;
  onClick: () => void;
}) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (updates: Partial<Inject>) => {
      return await client.updateInject({
        id: inject.id,
        number: updates.number ?? inject.number,
        due: updates.due ?? inject.due,
        completed: updates.completed ?? inject.completed,
        title: updates.title ?? inject.title,
        description: updates.description ?? inject.description,
        content: updates.content ?? inject.content,
        assigneeNames: inject.assignees.map((a) => a.name),
        submissionUrl: updates.submissionUrl ?? inject.submissionUrl,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["injects"] });
    },
  });

  const { timeLeft, isUrgent } = useCountdown(
    inject.due?.toDate(),
    inject.completed,
  );

  return (
    <TableRow
      onClick={onClick}
      className={cn(
        "cursor-pointer transition-all duration-300",
        isUrgent &&
          !inject.completed &&
          "border-l-2 border-l-destructive shadow-[inset_4px_0_8px_-4px_rgba(239,68,68,0.4)]",
      )}
    >
      {/* Status */}
      <TableCell className="text-center w-12">
        <div
          onClick={(e) => {
            e.stopPropagation();
            mutation.mutate({ completed: !inject.completed });
          }}
          className={cn(
            "p-1.5 rounded-md border inline-flex cursor-pointer hover:opacity-80 transition-opacity",
            inject.completed
              ? "bg-success/10 border-success/30 text-success"
              : "bg-muted border-border text-muted-foreground/30",
          )}
        >
          {inject.completed ? (
            <CheckCircle2 className="w-3.5 h-3.5" />
          ) : (
            <Circle className="w-3.5 h-3.5" />
          )}
        </div>
      </TableCell>

      {/* Inject # */}
      <TableCell>
        <span
          className={cn(
            "font-black font-mono text-sm tracking-tighter",
            isUrgent && !inject.completed ? "text-destructive" : "text-primary",
          )}
        >
          #{inject.number}
        </span>
      </TableCell>

      {/* Title */}
      <TableCell className="font-medium">{inject.title}</TableCell>

      {/* Countdown */}
      <TableCell>
        {!inject.completed && timeLeft ? (
          <div
            className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded border w-fit transition-colors",
              isUrgent
                ? "bg-destructive/20 border-destructive/50 text-destructive-foreground shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                : "bg-background border-border text-muted-foreground",
            )}
          >
            <Clock className={cn("w-3 h-3", isUrgent && "animate-bounce")} />
            <span className="text-[10px] font-bold font-mono">{timeLeft}</span>
          </div>
        ) : inject.completed ? (
          <span className="text-muted-foreground/40 text-xs">—</span>
        ) : null}
      </TableCell>

      {/* Assignees */}
      <TableCell>
        {inject.assignees.length > 0 ? (
          <div className="flex -space-x-1.5">
            {inject.assignees.map((a) => (
              <div
                key={a.id}
                className="w-6 h-6 rounded-full bg-muted border-2 border-card flex items-center justify-center text-[10px] font-bold text-muted-foreground"
                title={a.name}
              >
                {a.name.charAt(0).toUpperCase()}
              </div>
            ))}
          </div>
        ) : (
          <span className="text-muted-foreground/40 text-xs">—</span>
        )}
      </TableCell>

      {/* Description */}
      <TableCell className="text-muted-foreground text-xs max-w-[200px] truncate">
        {inject.description || "—"}
      </TableCell>
    </TableRow>
  );
}

// ─── Main page ───────────────────────────────────────────────
export function InjectsPage() {
  const search = useSearch({ from: "/injects" });
  const navigate = useNavigate({ from: "/injects" });
  const activeInjectId = search.injectId;
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<"number" | "title" | "completed">(
    "number",
  );
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");

  const setActiveInjectId = (id: number | null) => {
    navigate({
      search: (prev) => ({ ...prev, injectId: id ?? undefined }),
    });
  };

  const {
    data: injects,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ["injects"],
    queryFn: async () => {
      const res = await client.listInjects({});
      return res.injects;
    },
  });

  const filteredSorted = useMemo(() => {
    const all = injects ?? [];
    const normalizedQuery = query.trim().toLowerCase();

    const matchesQuery = (inject: Inject) => {
      if (!normalizedQuery) return true;
      const assigneeNames = inject.assignees.map((a) => a.name).join(" ");
      const haystack = [
        inject.number,
        inject.title,
        inject.description,
        assigneeNames,
        inject.completed ? "completed" : "pending",
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    };

    return all.filter(matchesQuery).sort((a, b) => {
      const dir = sortDirection === "asc" ? 1 : -1;
      if (sortKey === "number") {
        return (Number(a.number) - Number(b.number)) * dir;
      }
      if (sortKey === "title") {
        return a.title.localeCompare(b.title) * dir;
      }
      if (sortKey === "completed") {
        return (Number(a.completed) - Number(b.completed)) * dir;
      }
      return 0;
    });
  }, [injects, query, sortKey, sortDirection]);

  const selectedInject = injects?.find((i) => i.id === activeInjectId) || null;

  const toggleSort = (key: "number" | "title" | "completed") => {
    if (sortKey === key) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDirection("asc");
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
        Error loading injects: {error.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Injects
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Track and manage competition tasks
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search injects..."
            className="w-64 bg-background border-border"
          />
          <Button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Inject
          </Button>
        </div>
      </div>

      {injects?.length === 0 ? (
        <Empty>
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <ClipboardList className="h-8 w-8" />
            </EmptyMedia>
            <EmptyTitle>No injects found</EmptyTitle>
            <EmptyDescription>
              Injects will appear here once they are added
            </EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button
              onClick={() => setIsAddModalOpen(true)}
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
            >
              <Plus className="w-4 h-4 mr-2" />
              Add Inject
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12 text-center">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("completed")}
                >
                  Status
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead className="w-20">
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("number")}
                >
                  Inject #
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("title")}
                >
                  Title
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>Time Remaining</TableHead>
              <TableHead>Assignees</TableHead>
              <TableHead>Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredSorted.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className="text-center text-muted-foreground"
                >
                  No injects match your search.
                </TableCell>
              </TableRow>
            ) : (
              filteredSorted.map((inject) => (
                <InjectRow
                  key={inject.id}
                  inject={inject}
                  onClick={() => setActiveInjectId(inject.id)}
                />
              ))
            )}
          </TableBody>
        </Table>
      )}

      {isAddModalOpen && (
        <AddInjectModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
            setIsAddModalOpen(false);
            refetch();
          }}
        />
      )}

      {selectedInject && (
        <InjectDetailModal
          inject={selectedInject}
          onClose={() => setActiveInjectId(null)}
          onSuccess={() => {
            setActiveInjectId(null);
            refetch();
          }}
        />
      )}
    </div>
  );
}
