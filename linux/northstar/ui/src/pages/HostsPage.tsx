import React, { useMemo, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { client } from "../lib/client";
import { Host, Network } from "../gen/northstar_pb.ts";
import {
  ArrowUpDown,
  Plus,
  Server,
  Trash2,
  Upload,
  Shield,
  ShieldOff,
  Network as NetworkIcon,
  Pencil,
  X,
  Check,
} from "lucide-react";
import { Logo } from "../components/Logo";
import { AddHostModal } from "../components/AddHostModal";
import { ImportHostsModal } from "../components/ImportHostsModal";
import { HostDetailModal } from "../components/HostDetailModal";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useNavigate, useSearch, Link } from "@tanstack/react-router";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

function HostRow({
  host,
  onClick,
  updatePortMutation,
}: {
  host: Host;
  onClick: () => void;
  updatePortMutation: any;
}) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (updatedHost: Partial<Host>) => {
      return await client.updateHost({
        id: host.id,
        hostname: updatedHost.hostname ?? host.hostname,
        ip: updatedHost.ip ?? host.ip,
        osType: updatedHost.osType ?? host.osType,
        osVersion: updatedHost.osVersion ?? host.osVersion,
        role: updatedHost.role ?? host.role,
        passwordIndex: updatedHost.passwordIndex ?? host.passwordIndex,
        firewallEnabled: updatedHost.firewallEnabled ?? host.firewallEnabled,
        networkId: updatedHost.networkId ?? host.networkId,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  return (
    <TableRow onClick={onClick} className="cursor-pointer">
      <TableCell className="font-medium">{host.hostname}</TableCell>
      <TableCell className="font-mono text-sm">{host.ip}</TableCell>
      <TableCell>
        <div className="flex flex-col">
          <span>{host.osType}</span>
          <span className="text-muted-foreground text-xs">
            {host.osVersion}
          </span>
        </div>
      </TableCell>
      <TableCell>{host.role}</TableCell>
      <TableCell>
        <Badge
          variant="outline"
          onClick={(e) => {
            e.stopPropagation();
            mutation.mutate({ firewallEnabled: !host.firewallEnabled });
          }}
          className={cn(
            "cursor-pointer flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] w-max font-black uppercase tracking-wider transition-all border-2",
            host.firewallEnabled
              ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
              : "bg-destructive/20 text-destructive border-destructive/50 hover:bg-destructive/10",
          )}
        >
          {host.firewallEnabled ? (
            <Shield className="w-3 h-3" />
          ) : (
            <ShieldOff className="w-3 h-3" />
          )}
          {host.firewallEnabled ? "Active" : "Inactive"}
        </Badge>
      </TableCell>
      <TableCell>
        {host.hostPorts.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {host.hostPorts.map((port) => (
              <Badge
                key={port.port}
                variant="outline"
                onClick={(e) => {
                  e.stopPropagation();
                  updatePortMutation.mutate({
                    hostId: host.id,
                    port: port.port,
                    whitelisted: !port.whitelisted,
                  });
                }}
                className={cn(
                  "font-mono text-[10px] py-0 px-2 border justify-center transition-all select-none cursor-pointer",
                  port.whitelisted
                    ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
                    : "bg-destructive/20 text-destructive border-destructive/50 hover:bg-destructive/10",
                )}
              >
                {port.port}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-muted-foreground/40 text-xs font-mono font-bold">
            —
          </span>
        )}
      </TableCell>
      <TableCell>
        {host.passwordIndex !== undefined && host.passwordIndex !== null ? (
          <Link
            to="/passwords"
            search={{ highlight: host.passwordIndex }}
            onClick={(e) => e.stopPropagation()}
          >
            <Badge
              variant="outline"
              className="font-mono text-[10px] font-bold bg-primary/10 text-primary border-primary/30 hover:bg-primary/20 hover:border-primary/50 cursor-pointer transition-colors"
            >
              {host.passwordIndex}
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

function AddNetworkDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [name, setName] = useState("");
  const [cidr, setCidr] = useState("");
  const [description, setDescription] = useState("");
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async () => {
      return await client.addNetwork({ name, cidr, description });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["networks"] });
      toast.success("Network added");
      setName("");
      setCidr("");
      setDescription("");
      onOpenChange(false);
    },
    onError: (err: Error) => {
      toast.error(err.message);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[400px]">
        <DialogHeader>
          <DialogTitle>Add Network</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          <Input
            placeholder="Network name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            autoFocus
          />
          <Input
            placeholder="CIDR (e.g. 10.100.25.0/24)"
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
          />
          <Input
            placeholder="Description (optional)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => mutation.mutate()}
            disabled={!name || mutation.isPending}
          >
            {mutation.isPending ? "Adding..." : "Add Network"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NetworkGroupHeader({
  network,
  hostCount,
}: {
  network: Network | null;
  hostCount: number;
}) {
  const [isEditing, setIsEditing] = useState(false);
  const [editName, setEditName] = useState("");
  const [editCidr, setEditCidr] = useState("");
  const queryClient = useQueryClient();

  const updateMutation = useMutation({
    mutationFn: async () => {
      if (!network) return;
      return await client.updateNetwork({
        id: network.id,
        name: editName,
        cidr: editCidr,
        description: network.description,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["networks"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      setIsEditing(false);
      toast.success("Network updated");
    },
    onError: (err: Error) => {
      toast.error(err.message);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!network) return;
      return await client.deleteNetwork({ id: network.id });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["networks"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      toast.success("Network deleted");
    },
  });

  const startEdit = () => {
    if (!network) return;
    setEditName(network.name);
    setEditCidr(network.cidr);
    setIsEditing(true);
  };

  return (
    <TableRow className="bg-muted/30 hover:bg-muted/40 pointer-events-none">
      <TableCell colSpan={7} className="py-2 px-4">
        <div className="flex items-center gap-2 pointer-events-auto">
          <NetworkIcon className="w-3.5 h-3.5 text-primary/70" />
          {isEditing && network ? (
            <div className="flex items-center gap-2">
              <Input
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="h-6 w-32 text-xs"
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter") updateMutation.mutate();
                  if (e.key === "Escape") setIsEditing(false);
                }}
              />
              <Input
                value={editCidr}
                onChange={(e) => setEditCidr(e.target.value)}
                className="h-6 w-36 text-xs font-mono"
                placeholder="CIDR"
                onKeyDown={(e) => {
                  if (e.key === "Enter") updateMutation.mutate();
                  if (e.key === "Escape") setIsEditing(false);
                }}
              />
              <Button
                variant="ghost"
                size="icon"
                onClick={() => updateMutation.mutate()}
                className="h-5 w-5 text-success hover:bg-success/10"
              >
                <Check className="w-3 h-3" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsEditing(false)}
                className="h-5 w-5 text-muted-foreground hover:bg-muted"
              >
                <X className="w-3 h-3" />
              </Button>
            </div>
          ) : (
            <>
              <span className="text-sm font-semibold tracking-wide text-foreground">
                {network ? network.name : "Unassigned"}
              </span>
              {network?.cidr && (
                <span className="text-[10px] text-muted-foreground font-mono">
                  {network.cidr}
                </span>
              )}
              <span className="text-[10px] text-muted-foreground/80">
                — {hostCount} {hostCount === 1 ? "host" : "hosts"}
              </span>
              {network && (
                <div className="flex items-center gap-1 ml-2">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={startEdit}
                    className="h-5 w-5 text-muted-foreground hover:text-primary opacity-50 hover:opacity-100"
                  >
                    <Pencil className="w-2.5 h-2.5" />
                  </Button>
                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-5 w-5 text-muted-foreground hover:text-destructive opacity-50 hover:opacity-100"
                      >
                        <Trash2 className="w-2.5 h-2.5" />
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>
                          Delete network "{network.name}"?
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                          Hosts in this network will become unassigned. This
                          action cannot be undone.
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>Cancel</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => deleteMutation.mutate()}
                          className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                        >
                          Delete Network
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              )}
            </>
          )}
        </div>
      </TableCell>
    </TableRow>
  );
}

export function HostsPage() {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isAddNetworkOpen, setIsAddNetworkOpen] = useState(false);
  const [importContent, setImportContent] = useState<string | null>(null);
  const search = useSearch({ from: "/" });
  const navigate = useNavigate({ from: "/" });
  const activeHostId = search.hostId;
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<"hostname" | "ip" | "os" | "firewall">(
    "hostname",
  );
  const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");

  const setActiveHostId = (id: number | null) => {
    navigate({
      search: (prev) => ({ ...prev, hostId: id ?? undefined }),
    });
  };

  const queryClient = useQueryClient();

  const updatePortMutation = useMutation({
    mutationFn: async (payload: {
      hostId: number;
      port: number;
      whitelisted: boolean;
    }) => {
      return await client.updateHostPort(payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const clearMutation = useMutation({
    mutationFn: async () => {
      await client.clearHosts({});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      toast.success("All hosts cleared");
    },
    onError: (err: Error) => {
      toast.error("Failed to clear hosts: " + err.message);
    },
  });

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => {
      const res = await client.listHosts({});
      return res.hosts;
    },
  });

  const { data: networks } = useQuery({
    queryKey: ["networks"],
    queryFn: async () => {
      const res = await client.listNetworks({});
      return res.networks;
    },
  });

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result as string;
      if (!content) return;
      setImportContent(content);
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const selectedHost = data?.find((h) => h.id === activeHostId) || null;

  const groupedHosts = useMemo(() => {
    const hosts = data ?? [];
    const normalizedQuery = query.trim().toLowerCase();
    const matchesQuery = (host: Host) => {
      if (!normalizedQuery) return true;
      const ports = host.hostPorts.map((port) => String(port.port)).join(", ");
      const firewall = host.firewallEnabled ? "protected" : "exposed";
      const net = networks?.find((n) => n.id === host.networkId);
      const haystack = [
        host.hostname,
        host.ip,
        host.osType,
        host.osVersion,
        host.role,
        firewall,
        ports,
        net?.name,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(normalizedQuery);
    };

    const filtered = hosts.filter(matchesQuery).sort((a, b) => {
      const direction = sortDirection === "asc" ? 1 : -1;
      if (sortKey === "hostname") {
        return a.hostname.localeCompare(b.hostname) * direction;
      }
      if (sortKey === "ip") {
        return compareIp(a.ip, b.ip) * direction;
      }
      if (sortKey === "os") {
        return a.osType.localeCompare(b.osType) * direction;
      }
      if (sortKey === "firewall") {
        return (
          (Number(a.firewallEnabled) - Number(b.firewallEnabled)) * direction
        );
      }
      return 0;
    });

    // Group by network: include ALL networks (including empty ones) + unassigned
    const groups = new Map<
      number | null,
      { network: Network | null; hosts: Host[] }
    >();

    // Seed with all networks (so empty networks show in table)
    for (const net of networks ?? []) {
      groups.set(net.id, { network: net, hosts: [] });
    }
    // Add unassigned group
    if (!groups.has(null)) {
      groups.set(null, { network: null, hosts: [] });
    }

    // Distribute filtered hosts into their groups
    for (const host of filtered) {
      const netId =
        host.networkId !== undefined && host.networkId !== null
          ? host.networkId
          : null;
      if (!groups.has(netId)) {
        const net =
          netId !== null
            ? (networks?.find((n) => n.id === netId) ?? null)
            : null;
        groups.set(netId, { network: net, hosts: [] });
      }
      groups.get(netId)!.hosts.push(host);
    }

    // Sort groups: named networks first (alphabetically), unassigned last
    const entries = [...groups.entries()].sort(([aKey, aVal], [bKey, bVal]) => {
      if (aKey === null) return 1;
      if (bKey === null) return -1;
      return (aVal.network?.name ?? "").localeCompare(bVal.network?.name ?? "");
    });

    return entries;
  }, [data, query, networks, sortDirection, sortKey]);

  const toggleSort = (key: "hostname" | "ip" | "os" | "firewall") => {
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
        Error loading hosts: {error.message}
      </div>
    );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight text-foreground">
            Hosts
          </h2>
          <p className="text-muted-foreground text-sm mt-1">
            Manage infrastructure nodes and security status
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search hosts..."
            className="w-64 bg-background border-border"
          />
          <input
            type="file"
            accept=".toml"
            ref={fileInputRef}
            className="hidden"
            onChange={handleImport}
          />
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button
                variant="outline"
                className="font-bold text-destructive border-destructive/30 hover:bg-destructive/10"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Clear All
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Clear all hosts?</AlertDialogTitle>
                <AlertDialogDescription>
                  This will permanently delete all hosts, their services,
                  websites, and ports. This action cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={() => clearMutation.mutate()}
                  className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                >
                  Clear All Hosts
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
          <Button
            onClick={() => fileInputRef.current?.click()}
            variant="outline"
            className="font-bold"
          >
            <Upload className="w-4 h-4 mr-2" />
            Import TOML
          </Button>
          <Button
            onClick={() => setIsAddNetworkOpen(true)}
            variant="outline"
            className="font-bold"
          >
            <NetworkIcon className="w-4 h-4 mr-2" />
            Add Network
          </Button>
          <Button
            onClick={() => setIsAddModalOpen(true)}
            className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
          >
            <Plus className="w-4 h-4 mr-2" />
            Add Host
          </Button>
        </div>
      </div>

      {data?.length === 0 && (!networks || networks.length === 0) ? (
        <div className="col-span-full">
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Server className="h-8 w-8" />
              </EmptyMedia>
              <EmptyTitle>No hosts detected</EmptyTitle>
              <EmptyDescription>
                Add a host or network to start monitoring your infrastructure
              </EmptyDescription>
            </EmptyHeader>
            <EmptyContent>
              <Button
                onClick={() => setIsAddModalOpen(true)}
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-bold shadow-lg shadow-primary/20"
              >
                <Plus className="w-4 h-4 mr-2" />
                Add Host
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
                  onClick={() => toggleSort("hostname")}
                >
                  Hostname
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("ip")}
                >
                  IP Address
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("os")}
                >
                  OS
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>Role</TableHead>
              <TableHead>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="h-8 px-1"
                  onClick={() => toggleSort("firewall")}
                >
                  Firewall
                  <ArrowUpDown className="ml-1 h-3 w-3 text-muted-foreground" />
                </Button>
              </TableHead>
              <TableHead>Ports</TableHead>
              <TableHead>Password</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groupedHosts.every(([, group]) => group.hosts.length === 0) ? (
              <TableRow>
                <TableCell
                  colSpan={7}
                  className="text-center text-muted-foreground"
                >
                  {(data ?? []).length === 0
                    ? "No hosts yet. Import or add a host to get started."
                    : "No hosts match your search."}
                </TableCell>
              </TableRow>
            ) : (
              groupedHosts.map(([netId, group]) => (
                <React.Fragment key={`net-${netId ?? "unassigned"}`}>
                  <NetworkGroupHeader
                    network={group.network}
                    hostCount={group.hosts.length}
                  />
                  {group.hosts.map((host) => (
                    <HostRow
                      key={host.id}
                      host={host}
                      onClick={() => setActiveHostId(host.id)}
                      updatePortMutation={updatePortMutation}
                    />
                  ))}
                </React.Fragment>
              ))
            )}
          </TableBody>
        </Table>
      )}

      {isAddModalOpen && (
        <AddHostModal
          onClose={() => setIsAddModalOpen(false)}
          onSuccess={() => {
            setIsAddModalOpen(false);
            refetch();
          }}
        />
      )}

      {isAddNetworkOpen && (
        <AddNetworkDialog
          open={isAddNetworkOpen}
          onOpenChange={setIsAddNetworkOpen}
        />
      )}

      {importContent && (
        <ImportHostsModal
          content={importContent}
          onClose={() => setImportContent(null)}
          onSuccess={() => {
            setImportContent(null);
            refetch();
          }}
        />
      )}

      {selectedHost && (
        <HostDetailModal
          host={selectedHost}
          onClose={() => setActiveHostId(null)}
        />
      )}
    </div>
  );
}

function compareIp(a: string, b: string) {
  const normalize = (ip: string) =>
    ip
      .split(".")
      .map((part) => part.padStart(3, "0"))
      .join(".");
  return normalize(a).localeCompare(normalize(b));
}
