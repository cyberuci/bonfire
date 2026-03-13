import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { client } from "../lib/client";
import { Host, HostPort } from "../gen/northstar_pb.ts";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Server,
  Shield,
  ShieldOff,
  Trash2,
  Terminal,
  Activity,
  Globe,
  ArrowUpRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useNavigate, Link } from "@tanstack/react-router";
import { DetailTile } from "./DetailTile";
import { EditableField, EditableEnumField } from "./EditableField";
import { PortList } from "./PortList";
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

interface HostDetailModalProps {
  host: Host;
  onClose: () => void;
}

export function HostDetailModal({ host, onClose }: HostDetailModalProps) {
  const [editingField, setEditingField] = useState<string | null>(null);
  const navigate = useNavigate();

  const queryClient = useQueryClient();

  const { data: networks } = useQuery({
    queryKey: ["networks"],
    queryFn: async () => {
      const res = await client.listNetworks({});
      return res.networks;
    },
  });

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

  const portMutation = useMutation({
    mutationFn: async ({
      hostId,
      port,
      whitelisted,
    }: {
      hostId: number;
      port: number;
      whitelisted: boolean;
    }) => {
      return await client.updateHostPort({
        hostId,
        port,
        whitelisted,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const addPortMutation = useMutation({
    mutationFn: async (port: number) => {
      return await client.addHostPort({
        hostId: host.id,
        port,
        whitelisted: false,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const deletePortMutation = useMutation({
    mutationFn: async (item: HostPort) => {
      return await client.deleteHostPort({
        hostId: host.id,
        port: item.port,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await client.deleteHost({ id: host.id });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      onClose();
    },
  });

  const handleUpdate = (field: keyof Host, value: any) => {
    mutation.mutate({ [field]: value });
  };

  const handlePortToggle = (port: number, currentStatus: boolean) => {
    portMutation.mutate({
      hostId: host.id,
      port,
      whitelisted: !currentStatus,
    });
  };

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-[95vw] sm:max-w-5xl bg-background border-border text-foreground shadow-2xl shadow-black p-0 overflow-hidden">
        <DialogHeader className="border-b border-border px-6 py-4 bg-muted/40">
          <DialogTitle className="text-xl font-bold flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
                <Server className="w-5 h-5" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-bold text-muted-foreground uppercase tracking-widest leading-none mb-1">
                  Host Details
                </span>
                <span className="text-xl text-foreground">
                  {host.hostname}{" "}
                  <span className="text-muted-foreground font-mono text-sm ml-2">
                    [{host.ip}]
                  </span>
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 mr-6">
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
                      Are you absolutely sure?
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                      This action cannot be undone. This will permanently delete
                      the host <strong>{host.hostname}</strong> and all
                      associated services.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={() => deleteMutation.mutate()}
                      className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                    >
                      Delete Host
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>

              <Badge
                variant="outline"
                onClick={() =>
                  handleUpdate("firewallEnabled", !host.firewallEnabled)
                }
                className={cn(
                  "cursor-pointer flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2",
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
                {host.firewallEnabled ? "Firewall Active" : "Firewall Disabled"}
              </Badge>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 max-h-[80vh] overflow-y-auto custom-scrollbar">
          {/* Column 1: System Information */}
          <div className="space-y-6">
            <DetailTile title="System Information" icon={Server}>
              <div className="space-y-0.5">
                <EditableField
                  label="Hostname"
                  value={host.hostname}
                  isEditing={editingField === "hostname"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "hostname" : null)
                  }
                  onSave={(val) => handleUpdate("hostname", val)}
                />
                <EditableField
                  label="IP Address"
                  value={host.ip}
                  fontMono
                  isEditing={editingField === "ip"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "ip" : null)
                  }
                  onSave={(val) => handleUpdate("ip", val)}
                />
                <EditableEnumField
                  label="OS Type"
                  value={host.osType}
                  options={["Linux", "Windows", "Unknown"]}
                  isEditing={editingField === "osType"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "osType" : null)
                  }
                  onSave={(val) => handleUpdate("osType", val)}
                />
                <EditableField
                  label="OS Version"
                  value={host.osVersion}
                  isEditing={editingField === "osVersion"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "osVersion" : null)
                  }
                  onSave={(val) => handleUpdate("osVersion", val)}
                />
                <EditableField
                  label="Role"
                  value={host.role}
                  isEditing={editingField === "role"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "role" : null)
                  }
                  onSave={(val) => handleUpdate("role", val)}
                />
                <EditableEnumField
                  label="Network"
                  value={
                    networks?.find((n) => n.id === host.networkId)?.name ??
                    "None"
                  }
                  options={["None", ...(networks?.map((n) => n.name) ?? [])]}
                  isEditing={editingField === "networkId"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "networkId" : null)
                  }
                  onSave={(val) => {
                    if (val === "None") {
                      handleUpdate("networkId" as any, undefined);
                    } else {
                      const net = networks?.find((n) => n.name === val);
                      if (net) {
                        handleUpdate("networkId" as any, net.id);
                      }
                    }
                  }}
                />
              </div>
            </DetailTile>
          </div>

          {/* Column 2: Credentials & Ports */}
          <div className="space-y-6">
            <DetailTile title="Credentials" icon={Terminal}>
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-muted-foreground text-[11px] font-medium uppercase tracking-tight">
                    Username
                  </span>
                  <span className="text-foreground font-mono text-xs">
                    root / Administrator
                  </span>
                </div>
                <EditableEnumField
                  label="Password"
                  value={
                    host.passwordIndex !== undefined &&
                    host.passwordIndex !== null
                      ? `${host.passwordIndex}`
                      : "None"
                  }
                  options={[
                    "None",
                    ...Array.from({ length: 90 }, (_, i) => `${i}`),
                  ]}
                  isEditing={editingField === "passwordIndex"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "passwordIndex" : null)
                  }
                  onSave={(val) => {
                    if (val === "None") {
                      handleUpdate("passwordIndex" as any, undefined);
                    } else {
                      handleUpdate("passwordIndex" as any, parseInt(val));
                    }
                  }}
                  renderValue={(val) =>
                    val !== "None" ? (
                      <Link
                        to="/passwords"
                        search={{ highlight: parseInt(val) }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <Badge
                          variant="outline"
                          className="font-mono text-[10px] font-bold bg-primary/10 text-primary border-primary/30 hover:bg-primary/20 hover:border-primary/50 cursor-pointer transition-colors"
                        >
                          {val}
                        </Badge>
                      </Link>
                    ) : (
                      <span className="text-muted-foreground/40 font-mono text-xs font-bold">
                        —
                      </span>
                    )
                  }
                />
              </div>
            </DetailTile>

            <PortList
              title="Firewall Rules"
              icon={Shield}
              items={host.hostPorts}
              getPort={(hp) => hp.port}
              onAdd={(port) => addPortMutation.mutate(port)}
              onDelete={(hp) => deletePortMutation.mutate(hp)}
              onViewClick={(hp) => handlePortToggle(hp.port, hp.whitelisted)}
              viewBadgeVariant={(hp) =>
                hp.whitelisted
                  ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
                  : "bg-destructive/20 text-destructive border-destructive/50 hover:bg-destructive/10"
              }
              description="Click a port to toggle its firewall status."
            />
          </div>

          {/* Column 3: Active Services */}
          <div className="lg:h-full">
            <DetailTile
              title="Active Services"
              icon={Activity}
              noPadding
              className="h-full flex flex-col"
            >
              <ScrollArea className="h-[300px] w-full p-4">
                <div className="space-y-3 pb-4">
                  {host.services.length > 0 ? (
                    host.services.map((service) => (
                      <Card
                        key={service.id}
                        onClick={() => {
                          onClose();
                          navigate({
                            to: "/services",
                            search: { serviceId: service.id },
                          });
                        }}
                        className="group/service bg-card/40 border-border hover:border-primary/30 transition-colors shadow-none py-0 gap-0 cursor-pointer"
                      >
                        <CardHeader className="p-3 pb-1 border-none gap-1">
                          <div className="flex justify-between items-start">
                            <h5 className="font-bold text-foreground text-xs tracking-tight group-hover/service:text-primary transition-colors flex items-center gap-1.5">
                              {service.name}
                              <ArrowUpRight className="w-2.5 h-2.5 opacity-0 group-hover/service:opacity-100 transition-opacity" />
                            </h5>
                            {service.scored && (
                              <Badge
                                variant="outline"
                                className="bg-primary/10 text-primary border-primary/20 text-[8px] px-1 py-0 font-black uppercase tracking-tighter"
                              >
                                Scored
                              </Badge>
                            )}
                          </div>
                          <p className="text-[10px] text-muted-foreground leading-none">
                            {service.technology}
                          </p>
                        </CardHeader>
                        <CardContent className="p-3 pt-2">
                          {service.websites.length > 0 ? (
                            <div className="space-y-1.5 pt-2 border-t border-border/50">
                              {service.websites.map((site) => (
                                <div
                                  key={site.id}
                                  className="flex items-center gap-2 text-[10px] text-info/80"
                                >
                                  <Globe className="w-3 h-3 shrink-0" />
                                  <span className="truncate">
                                    {site.name || site.url}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-[10px] text-muted-foreground italic">
                              No web interfaces
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))
                  ) : (
                    <div className="text-center py-20">
                      <Activity className="w-8 h-8 text-muted-foreground mx-auto mb-3 opacity-20" />
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold">
                        No active services
                      </p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </DetailTile>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
