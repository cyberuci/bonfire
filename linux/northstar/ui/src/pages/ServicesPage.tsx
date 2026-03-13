import React, { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { client } from "../lib/client";
import { Service } from "../gen/northstar_pb.ts";
import {
  ArrowUpDown,
  Database,
  History,
  Lock,
  Plus,
  Server,
  Shield,
  ShieldOff,
  Network,
} from "lucide-react";
import { Logo } from "../components/Logo";
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
import { ServiceDetailModal } from "../components/ServiceDetailModal";
import { AddServiceModal } from "../components/AddServiceModal";
import { useNavigate, useSearch, Link } from "@tanstack/react-router";

function ServiceRow({
  service,
  onClick,
}: {
  service: Service;
  onClick: () => void;
}) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (updatedService: Partial<Service>) => {
      return await client.updateService({
        id: service.id,
        name: updatedService.name ?? service.name,
        technology: updatedService.technology ?? service.technology,
        scored: updatedService.scored ?? service.scored,
        disabled: updatedService.disabled ?? service.disabled,
        backedUp: updatedService.backedUp ?? service.backedUp,
        hardened: updatedService.hardened ?? service.hardened,
        ldapAuthentication:
          updatedService.ldapAuthentication ?? service.ldapAuthentication,
        hostId: updatedService.hostId ?? service.hostId,
        passwordIndex:
          "passwordIndex" in updatedService
            ? updatedService.passwordIndex
            : service.passwordIndex,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const handleToggle = (field: keyof Service) => {
    mutation.mutate({ [field]: !service[field] });
  };

  return (
    <TableRow onClick={onClick} className="cursor-pointer">
      <TableCell className="font-medium">{service.name}</TableCell>
      <TableCell className="text-muted-foreground font-mono text-xs">
        {service.technology}
      </TableCell>
      <TableCell>
        <Badge
          variant={service.scored ? "outline" : "secondary"}
          onClick={(e) => {
            e.stopPropagation();
            handleToggle("scored");
          }}
          className={cn(
            "text-[9px] px-2 py-0 font-black uppercase tracking-widest cursor-pointer transition-colors border",
            service.scored
              ? "bg-primary/10 text-primary border-primary/20 hover:bg-primary/20 hover:border-primary/40"
              : "bg-muted/50 text-muted-foreground/40 border-transparent hover:bg-muted hover:text-muted-foreground/80",
          )}
        >
          Scored
        </Badge>
      </TableCell>
      <TableCell>
        <Badge
          variant="outline"
          onClick={(e) => {
            e.stopPropagation();
            handleToggle("disabled");
          }}
          className={cn(
            "cursor-pointer flex w-max items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2",
            !service.disabled
              ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
              : "bg-destructive/20 text-destructive border-destructive/50 hover:bg-destructive/10",
          )}
        >
          {service.disabled ? (
            <ShieldOff className="w-3 h-3" />
          ) : (
            <Shield className="w-3 h-3" />
          )}
          {service.disabled ? "Offline" : "Active"}
        </Badge>
      </TableCell>
      <TableCell className="text-center">
        <div
          onClick={(e) => {
            e.stopPropagation();
            handleToggle("hardened");
          }}
          className={cn(
            "p-1.5 rounded-md border inline-flex cursor-pointer hover:opacity-80 transition-opacity",
            service.hardened
              ? "bg-success/10 border-success/30 text-success"
              : "bg-muted border-border text-muted-foreground/30",
          )}
        >
          <Lock className="w-3.5 h-3.5" />
        </div>
      </TableCell>
      <TableCell className="text-center">
        <div
          onClick={(e) => {
            e.stopPropagation();
            handleToggle("backedUp");
          }}
          className={cn(
            "p-1.5 rounded-md border inline-flex cursor-pointer hover:opacity-80 transition-opacity",
            service.backedUp
              ? "bg-success/10 border-success/30 text-success"
              : "bg-muted border-border text-muted-foreground/30",
          )}
        >
          <History className="w-3.5 h-3.5" />
        </div>
      </TableCell>
      <TableCell className="text-center">
        <div
          onClick={(e) => {
            e.stopPropagation();
            handleToggle("ldapAuthentication");
          }}
          className={cn(
            "p-1.5 rounded-md border inline-flex cursor-pointer hover:opacity-80 transition-opacity",
            service.ldapAuthentication
              ? "bg-success/10 border-success/30 text-success"
              : "bg-muted border-border text-muted-foreground/30",
          )}
        >
          <Database className="w-3.5 h-3.5" />
        </div>
      </TableCell>
      <TableCell className="text-muted-foreground text-xs">
        {service.servicePorts.length > 0
          ? service.servicePorts.map((p) => p.port).join(", ")
          : "—"}
      </TableCell>
      <TableCell>
        {service.passwordIndex !== undefined &&
        service.passwordIndex !== null ? (
          <Link
            to="/passwords"
            search={{ highlight: service.passwordIndex }}
            onClick={(e) => e.stopPropagation()}
          >
            <Badge
              variant="outline"
              className="font-mono text-[10px] font-bold bg-primary/10 text-primary border-primary/30 hover:bg-primary/20 hover:border-primary/50 cursor-pointer transition-colors"
            >
              {service.passwordIndex}
            </Badge>
          </Link>
        ) : (
          <span className="text-muted-foreground/40 font-mono text-xs font-bold">
            —
          </span>
        )}
      </TableCell>
      <TableCell>
        {service.dependencies.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {service.dependencies.map((dep) => (
              <Badge
                key={dep.dependsOnId}
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  onClick();
                }}
                className="text-[10px] font-medium gap-1 border-info/30 text-info cursor-pointer hover:bg-info/10 transition-colors"
              >
                <Network className="w-2.5 h-2.5" />
                {dep.dependsOnName || `#${dep.dependsOnId}`}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-muted-foreground/40 text-xs font-mono font-bold">
            —
          </span>
        )}
      </TableCell>
    </TableRow>
  );
}

export function ServicesPage() {
  const search = useSearch({ from: "/services" });
  const navigate = useNavigate({ from: "/services" });
  const activeServiceId = search.serviceId;
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<"host" | "name" | "technology">(
    "host",
  );
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");

  const setActiveServiceId = (id: number | null) => {
    navigate({
      search: (prev) => ({ ...prev, serviceId: id ?? undefined }),
    });
  };

  const {
    data: services,
    isLoading: servicesLoading,
    error: servicesError,
    refetch,
  } = useQuery({
    queryKey: ["services"],
    queryFn: async () => {
      const res = await client.listServices({});
      return res.services;
    },
  });

  const { data: hosts, isLoading: hostsLoading } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => {
      const res = await client.listHosts({});
      return res.hosts;
    },
  });

  const hostMap = useMemo(() => {
    const map = new Map<number, string>();
    hosts?.forEach((h) => map.set(h.id, h.hostname || h.ip));
    return map;
  }, [hosts]);

  const groupedServices = useMemo(() => {
    const all = services ?? [];
    const normalizedQuery = query.trim().toLowerCase();

    const matchesQuery = (service: Service) => {
      if (!normalizedQuery) return true;
      const hostName = hostMap.get(service.hostId) ?? "Unknown";
      const ports = service.servicePorts.map((p) => String(p.port)).join(", ");
      const status = service.disabled ? "disabled" : "running";
      const scored = service.scored ? "scored" : "";
      const haystack = [
        service.name,
        service.technology,
        hostName,
        status,
        scored,
        ports,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    };

    const filtered = all.filter(matchesQuery);

    // Sort services within each group
    const sorted = filtered.sort((a, b) => {
      const direction = sortDirection === "asc" ? 1 : -1;
      if (sortKey === "host") {
        const hostA = hostMap.get(a.hostId) ?? "";
        const hostB = hostMap.get(b.hostId) ?? "";
        const hostCmp = hostA.localeCompare(hostB) * direction;
        return hostCmp !== 0 ? hostCmp : a.name.localeCompare(b.name);
      }
      if (sortKey === "name") {
        return a.name.localeCompare(b.name) * direction;
      }
      if (sortKey === "technology") {
        return a.technology.localeCompare(b.technology) * direction;
      }
      return 0;
    });

    // Group by host, preserving the sorted order
    const groups = new Map<number, { hostname: string; services: Service[] }>();
    for (const service of sorted) {
      const hostId = service.hostId;
      if (!groups.has(hostId)) {
        groups.set(hostId, {
          hostname: hostMap.get(hostId) ?? "Unknown Host",
          services: [],
        });
      }
      groups.get(hostId)!.services.push(service);
    }

    return [...groups.entries()];
  }, [services, hosts, query, sortKey, sortDirection, hostMap]);

  const totalFiltered = groupedServices.reduce(
    (sum, [, g]) => sum + g.services.length,
    0,
  );

  const selectedService =
    services?.find((s) => s.id === activeServiceId) || null;

  const toggleSort = (key: "host" | "name" | "technology") => {
    if (sortKey === key) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
      return;
    }
    setSortKey(key);
    setSortDirection("asc");
  };

  if (servicesLoading || hostsLoading)
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground animate-pulse">
        <Logo className="w-8 h-8 animate-spin opacity-20" />
      </div>
    );

  if (servicesError)
    return (
      <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive">
        Error loading services: {servicesError.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Services
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Monitor and manage application services
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search services..."
            className="w-64 bg-background border-border"
          />
          <Button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Service
          </Button>
        </div>
      </div>

      {services?.length === 0 ? (
        <div className="col-span-full">
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Shield className="h-8 w-8" />
              </EmptyMedia>
              <EmptyTitle>No services found</EmptyTitle>
              <EmptyDescription>
                Services will appear here once they are added or detected
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button
                onClick={() => setIsAddModalOpen(true)}
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Service
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
                  Service Name
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("technology")}
                >
                  Technology
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>Scored</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-center">Hardened</TableHead>
              <TableHead className="text-center">Backup</TableHead>
              <TableHead className="text-center">LDAP</TableHead>
              <TableHead>Ports</TableHead>
              <TableHead>Password</TableHead>
              <TableHead>Dependencies</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {totalFiltered === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={10}
                  className="text-center text-muted-foreground"
                >
                  No services match your search.
                </TableCell>
              </TableRow>
            ) : (
              groupedServices.map(([hostId, group]) => (
                <React.Fragment key={`group-${hostId}`}>
                  {/* Host group header */}
                  <TableRow
                    key={`host-${hostId}`}
                    className="bg-muted/30 hover:bg-muted/40 pointer-events-none"
                  >
                    <TableCell colSpan={10} className="py-2 px-4">
                      <div className="flex items-center gap-2">
                        <Server className="w-3.5 h-3.5 text-primary/70" />
                        <span className="text-sm font-semibold tracking-wide text-foreground">
                          {group.hostname}
                        </span>
                        <span className="text-[10px] text-muted-foreground/80">
                          — {group.services.length}{" "}
                          {group.services.length === 1 ? "service" : "services"}
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                  {group.services.map((service) => (
                    <ServiceRow
                      key={service.id}
                      service={service}
                      onClick={() => setActiveServiceId(service.id)}
                    />
                  ))}
                </React.Fragment>
              ))
            )}
          </TableBody>
        </Table>
      )}

      {isAddModalOpen && (
        <AddServiceModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
            setIsAddModalOpen(false);
            refetch();
          }}
        />
      )}

      {selectedService && (
        <ServiceDetailModal
          service={selectedService}
          onClose={() => setActiveServiceId(null)}
        />
      )}
    </div>
  );
}
