import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { client } from "@/lib/client";
import { Website } from "@/gen/northstar_pb";
import { AddWebsiteModal } from "@/components/AddWebsiteModal";
import { WebsiteDetailModal } from "@/components/WebsiteDetailModal";
import { Logo } from "@/components/Logo";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import {
  ArrowUpDown,
  ExternalLink,
  Globe,
  Plus,
  CheckCircle2,
  Circle,
} from "lucide-react";
import { useNavigate, useSearch, Link } from "@tanstack/react-router";

function WebsiteRow({
  website,
  onClick,
  getServiceLabel,
}: {
  website: Website;
  onClick: () => void;
  getServiceLabel: (serviceId: number) => string;
}) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (updatedWebsite: Partial<Website>) => {
      return await client.updateWebsite({
        id: website.id,
        name: updatedWebsite.name ?? website.name,
        url: updatedWebsite.url ?? website.url,
        username: updatedWebsite.username ?? website.username,
        passwordIndex: updatedWebsite.passwordIndex ?? website.passwordIndex,
        oldPassword: updatedWebsite.oldPassword ?? website.oldPassword,
        serviceId: updatedWebsite.serviceId ?? website.serviceId,
        enumerated: updatedWebsite.enumerated ?? website.enumerated,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["websites"] });
    },
  });

  const handleUpdate = (field: keyof Website, value: any) => {
    mutation.mutate({ [field]: value });
  };

  return (
    <TableRow onClick={onClick} className="cursor-pointer">
      <TableCell className="font-medium">
        <div className="flex items-center gap-2">
          {website.name}
          {website.url && (
            <a
              href={
                website.url.startsWith("http")
                  ? website.url
                  : `https://${website.url}`
              }
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary transition-colors font-mono"
            >
              {website.url}
              <ExternalLink className="w-3 h-3 shrink-0" />
            </a>
          )}
        </div>
      </TableCell>
      <TableCell>
        {website.serviceId > 0 ? (
          <Badge
            variant="secondary"
            className="bg-muted text-muted-foreground text-[10px] py-0 px-2 font-medium border-none"
          >
            {getServiceLabel(website.serviceId)}
          </Badge>
        ) : (
          <span className="text-muted-foreground/40">—</span>
        )}
      </TableCell>
      <TableCell>
        <Badge
          variant="outline"
          onClick={(e) => {
            e.stopPropagation();
            handleUpdate("enumerated", !website.enumerated);
          }}
          className={cn(
            "cursor-pointer flex items-center w-max gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2 select-none",
            website.enumerated
              ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
              : "bg-warning/20 text-warning border-warning/50 hover:bg-warning/10",
          )}
        >
          {website.enumerated ? (
            <CheckCircle2 className="w-3 h-3" />
          ) : (
            <Circle className="w-3 h-3" />
          )}
          {website.enumerated ? "Complete" : "In Progress"}
        </Badge>
      </TableCell>
      <TableCell className="text-muted-foreground font-mono text-xs">
        {website.username || "—"}
      </TableCell>
      <TableCell>
        {website.passwordIndex !== undefined &&
        website.passwordIndex !== null ? (
          <Link
            to="/passwords"
            search={{ highlight: website.passwordIndex }}
            onClick={(e) => e.stopPropagation()}
          >
            <Badge
              variant="outline"
              className="font-mono text-[10px] font-bold bg-primary/10 text-primary border-primary/30 hover:bg-primary/20 hover:border-primary/50 cursor-pointer transition-colors"
            >
              {website.passwordIndex}
            </Badge>
          </Link>
        ) : (
          <span className="text-muted-foreground/40 font-mono text-xs font-bold">
            —
          </span>
        )}
      </TableCell>
    </TableRow>
  );
}

export function WebsitesPage() {
  const search = useSearch({ from: "/websites" });
  const navigate = useNavigate({ from: "/websites" });
  const activeWebsiteId = search.websiteId;
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<"name" | "service">("name");
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");

  const setActiveWebsiteId = (id: number | null) => {
    navigate({
      search: (prev) => ({ ...prev, websiteId: id ?? undefined }),
    });
  };

  const {
    data: websites,
    isLoading: websitesLoading,
    error: websitesError,
    refetch,
  } = useQuery({
    queryKey: ["websites"],
    queryFn: async () => {
      const response = await client.listWebsites({});
      return response.websites;
    },
  });

  const { data: services, isLoading: servicesLoading } = useQuery({
    queryKey: ["services"],
    queryFn: async () => {
      const response = await client.listServices({});
      return response.services;
    },
  });

  const { data: hosts } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => {
      const response = await client.listHosts({});
      return response.hosts;
    },
  });

  const serviceMap = useMemo(() => {
    const map = new Map<number, { name: string; hostName: string }>();
    services?.forEach((s) => {
      const host = hosts?.find((h) => h.id === s.hostId);
      map.set(s.id, {
        name: s.name,
        hostName: host?.hostname || host?.ip || "Unknown",
      });
    });
    return map;
  }, [services, hosts]);

  const getServiceLabel = (serviceId: number): string => {
    const info = serviceMap.get(serviceId);
    if (!info) return `Service #${serviceId}`;
    return `${info.hostName} / ${info.name}`;
  };

  const filteredWebsites = useMemo(() => {
    const all = websites ?? [];
    const normalizedQuery = query.trim().toLowerCase();

    const matchesQuery = (website: Website) => {
      if (!normalizedQuery) return true;
      const serviceLabel =
        website.serviceId > 0 ? getServiceLabel(website.serviceId) : "";
      const status = website.enumerated ? "complete" : "in-progress";
      const haystack = [
        website.name,
        website.url,
        website.username,
        serviceLabel,
        status,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    };

    return all.filter(matchesQuery).sort((a, b) => {
      const direction = sortDirection === "asc" ? 1 : -1;
      if (sortKey === "name") {
        return a.name.localeCompare(b.name) * direction;
      }
      if (sortKey === "service") {
        // Group by service; websites with no service sink to the bottom (or top when desc)
        const labelA =
          a.serviceId > 0 ? getServiceLabel(a.serviceId) : "\uffff";
        const labelB =
          b.serviceId > 0 ? getServiceLabel(b.serviceId) : "\uffff";
        const cmp = labelA.localeCompare(labelB) * direction;
        return cmp !== 0 ? cmp : a.name.localeCompare(b.name);
      }
      return 0;
    });
  }, [websites, query, sortKey, sortDirection, serviceMap]);

  const selectedWebsite =
    websites?.find((w) => w.id === activeWebsiteId) || null;

  const toggleSort = (key: "name" | "service") => {
    if (sortKey === key) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDirection("asc");
  };

  if (websitesLoading || servicesLoading)
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground animate-pulse">
        <Logo className="w-8 h-8 animate-spin opacity-20" />
      </div>
    );

  if (websitesError)
    return (
      <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
        Error loading websites: {websitesError.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Websites
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor and manage web services and credentials
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search websites..."
            className="w-64 bg-background border-border"
          />
          <Button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Website
          </Button>
        </div>
      </div>

      {websites?.length === 0 ? (
        <div className="col-span-full">
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Globe className="h-8 w-8" />
              </EmptyMedia>
              <EmptyTitle>No websites monitored</EmptyTitle>
              <EmptyDescription>
                Add a website to start tracking uptime and credentials
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button
                onClick={() => setIsAddModalOpen(true)}
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Website
              </Button>
            </EmptyContent>
          </Empty>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("name")}
                >
                  Name
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("service")}
                >
                  Service
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Username</TableHead>
              <TableHead>Password</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredWebsites.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="text-center text-muted-foreground"
                >
                  No websites match your search.
                </TableCell>
              </TableRow>
            ) : (
              filteredWebsites.map((website) => (
                <WebsiteRow
                  key={website.id}
                  website={website}
                  onClick={() => setActiveWebsiteId(website.id)}
                  getServiceLabel={getServiceLabel}
                />
              ))
            )}
          </TableBody>
        </Table>
      )}

      {isAddModalOpen && (
        <AddWebsiteModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
            setIsAddModalOpen(false);
            refetch();
          }}
        />
      )}

      {selectedWebsite && (
        <WebsiteDetailModal
          website={selectedWebsite}
          onClose={() => setActiveWebsiteId(null)}
        />
      )}
    </div>
  );
}
