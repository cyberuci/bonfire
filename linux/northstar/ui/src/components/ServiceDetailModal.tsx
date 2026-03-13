import { useState } from "react";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { client } from "../lib/client";
import { Service, ServicePort } from "../gen/northstar_pb.ts";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Zap,
  Shield,
  ShieldOff,
  Globe,
  Trash2,
  Check,
  X,
  Lock,
  History,
  Database,
  Power,
  Star,
  ArrowUpRight,
  Server,
  Plus,
  Unlink,
  Pencil,
  Network,
} from "lucide-react";
import { cn, ensureAbsoluteUrl } from "@/lib/utils";
import { useNavigate, Link } from "@tanstack/react-router";
import { SearchableSelect } from "@/components/ui/searchable-select";
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

interface ServiceDetailModalProps {
  service: Service;
  onClose: () => void;
}

export function ServiceDetailModal({
  service,
  onClose,
}: ServiceDetailModalProps) {
  const [editingField, setEditingField] = useState<string | null>(null);
  const [isAddingWebsite, setIsAddingWebsite] = useState(false);
  const [selectedWebsiteId, setSelectedWebsiteId] = useState<string>("");
  const [isAddingDep, setIsAddingDep] = useState(false);
  const [selectedDepId, setSelectedDepId] = useState<string>("");
  const navigate = useNavigate();

  const queryClient = useQueryClient();

  const { data: hosts } = useQuery({
    queryKey: ["hosts"],
    queryFn: async () => {
      const res = await client.listHosts({});
      return res.hosts;
    },
  });

  const { data: allServices } = useQuery({
    queryKey: ["services"],
    queryFn: async () => {
      const res = await client.listServices({});
      return res.services;
    },
  });

  const { data: websites } = useQuery({
    queryKey: ["websites"],
    queryFn: async () => {
      const res = await client.listWebsites({});
      return res.websites;
    },
  });

  const host = hosts?.find((h) => h.id === service.hostId);
  const unassociatedWebsites = websites?.filter((w) => w.serviceId === 0) || [];

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

  const websiteMutation = useMutation({
    mutationFn: async ({
      websiteId,
      serviceId,
    }: {
      websiteId: number;
      serviceId: number;
    }) => {
      const website = websites?.find((w) => w.id === websiteId);
      if (!website) return;
      return await client.updateWebsite({
        id: website.id,
        name: website.name,
        url: website.url,
        username: website.username,
        passwordIndex: website.passwordIndex,
        oldPassword: website.oldPassword,
        serviceId: serviceId,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["websites"] });
      setIsAddingWebsite(false);
      setSelectedWebsiteId("");
    },
  });

  const addPortMutation = useMutation({
    mutationFn: async (port: number) => {
      return await client.addServicePort({
        serviceId: service.id,
        port,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
    },
  });

  const deletePortMutation = useMutation({
    mutationFn: async (item: ServicePort) => {
      return await client.deleteServicePort({
        serviceId: service.id,
        port: item.port,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
    },
  });

  const addDepMutation = useMutation({
    mutationFn: async (dependsOnId: number) => {
      await client.addServiceDependency({
        serviceId: service.id,
        dependsOnId,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      setIsAddingDep(false);
      setSelectedDepId("");
    },
  });

  const removeDepMutation = useMutation({
    mutationFn: async (dependsOnId: number) => {
      await client.deleteServiceDependency({
        serviceId: service.id,
        dependsOnId,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await client.deleteService({ id: service.id });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["services"] });
      onClose();
    },
  });

  const handleToggle = (field: keyof Service) => {
    mutation.mutate({ [field]: !service[field] });
  };

  const handleUpdate = (field: keyof Service, value: any) => {
    mutation.mutate({ [field]: value });
  };

  const availableForDep =
    allServices?.filter(
      (s) =>
        s.id !== service.id &&
        !service.dependencies.some((d) => d.dependsOnId === s.id),
    ) ?? [];

  const handleAddWebsite = () => {
    if (selectedWebsiteId) {
      websiteMutation.mutate({
        websiteId: parseInt(selectedWebsiteId),
        serviceId: service.id,
      });
    }
  };

  const handleRemoveWebsite = (websiteId: number) => {
    websiteMutation.mutate({
      websiteId: websiteId,
      serviceId: 0,
    });
  };

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-[95vw] sm:max-w-5xl bg-background border-border text-foreground shadow-2xl shadow-black p-0 overflow-hidden">
        <DialogHeader className="border-b border-border px-6 py-4 bg-muted/40">
          <DialogTitle className="text-xl font-bold flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
                <Zap className="w-5 h-5" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-bold text-muted-foreground uppercase tracking-widest leading-none mb-1">
                  Service Profile
                </span>
                <span className="text-xl text-foreground">{service.name}</span>
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
                    <AlertDialogTitle>Delete {service.name}?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This action cannot be undone. This will permanently delete
                      the service and all associated ports.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={() => deleteMutation.mutate()}
                      className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                    >
                      Delete Service
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>

              {service.scored && (
                <Badge
                  variant="outline"
                  className="bg-primary/10 text-primary border-primary/20 text-[10px] px-2 py-1 font-black uppercase tracking-wider"
                >
                  Scored Asset
                </Badge>
              )}
              <Badge
                variant="outline"
                onClick={() => handleToggle("disabled")}
                className={cn(
                  "cursor-pointer flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2",
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
                {service.disabled ? "Service Offline" : "Service Active"}
              </Badge>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 max-h-[80vh] overflow-y-auto custom-scrollbar">
          {/* Column 1: Core Configuration */}
          <div className="space-y-6">
            <DetailTile title="Service Information" icon={Zap}>
              <div className="space-y-0.5">
                <EditableField
                  label="Name"
                  value={service.name}
                  isEditing={editingField === "name"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "name" : null)
                  }
                  onSave={(val) => handleUpdate("name", val)}
                />
                <EditableField
                  label="Technology"
                  value={service.technology}
                  isEditing={editingField === "technology"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "technology" : null)
                  }
                  onSave={(val) => handleUpdate("technology", val)}
                />
                <EditableEnumField
                  label="Password"
                  value={
                    service.passwordIndex !== undefined &&
                    service.passwordIndex !== null
                      ? `${service.passwordIndex}`
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
                <div className="flex justify-between items-center py-1 group/host">
                  <span className="text-muted-foreground text-[11px] font-medium uppercase tracking-tight">
                    Parent Host
                  </span>
                  {editingField === "hostId" ? (
                    <div className="flex items-center gap-1">
                      <SearchableSelect
                        value={service.hostId.toString()}
                        onValueChange={(val) => {
                          handleUpdate("hostId", parseInt(val));
                          setEditingField(null);
                        }}
                        options={
                          hosts?.map((h) => ({
                            value: h.id.toString(),
                            label: `${h.hostname} (${h.ip})`,
                          })) ?? []
                        }
                        placeholder="Select Host"
                        triggerClassName="h-7 w-[150px] bg-background border-primary/50 text-foreground text-xs"
                      />
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => setEditingField(null)}
                        className="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                      >
                        <X className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          onClose();
                          navigate({
                            to: "/",
                            search: { hostId: service.hostId },
                          });
                        }}
                        className="h-7 px-2 text-primary hover:text-primary/80 hover:bg-primary/10 flex items-center gap-1.5"
                      >
                        <Server className="w-3 h-3" />
                        <span className="text-xs font-mono">
                          {host?.hostname || `#${service.hostId}`}
                        </span>
                        <ArrowUpRight className="w-3 h-3 opacity-0 group-hover/host:opacity-100 transition-opacity" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => setEditingField("hostId")}
                        className="h-6 w-6 text-muted-foreground hover:text-primary opacity-0 group-hover/host:opacity-100 transition-opacity"
                      >
                        <Pencil className="w-3 h-3" />
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            </DetailTile>

            <DetailTile title="Compliance & Security" icon={Lock}>
              <div className="space-y-3">
                <StatusToggle
                  label="Hardening"
                  active={service.hardened}
                  onClick={() => handleToggle("hardened")}
                  icon={<Lock className="w-3.5 h-3.5" />}
                />
                <StatusToggle
                  label="Backups"
                  active={service.backedUp}
                  onClick={() => handleToggle("backedUp")}
                  icon={<History className="w-3.5 h-3.5" />}
                />
                <StatusToggle
                  label="LDAP Auth"
                  active={service.ldapAuthentication}
                  onClick={() => handleToggle("ldapAuthentication")}
                  icon={<Database className="w-3.5 h-3.5" />}
                />
                <StatusToggle
                  label="Scoring"
                  active={service.scored}
                  onClick={() => handleToggle("scored")}
                  icon={<Star className="w-3.5 h-3.5" />}
                />
              </div>
            </DetailTile>
          </div>

          {/* Column 2: Interfaces & Ports */}
          <div className="space-y-6">
            <PortList
              title="Service Ports"
              icon={Power}
              items={service.servicePorts}
              getPort={(sp) => sp.port}
              onAdd={(port) => addPortMutation.mutate(port)}
              onDelete={(sp) => deletePortMutation.mutate(sp)}
              viewBadgeVariant={() =>
                "bg-muted text-muted-foreground border-border"
              }
              emptyMessage="No ports assigned"
            />

            <DetailTile
              title="Web Interfaces"
              icon={Globe}
              noPadding
              headerAction={
                !isAddingWebsite && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setIsAddingWebsite(true)}
                    className="h-6 w-6 text-muted-foreground hover:text-primary"
                  >
                    <Plus className="w-3 h-3" />
                  </Button>
                )
              }
            >
              <ScrollArea className="h-[200px] w-full p-4">
                <div className="space-y-2">
                  {isAddingWebsite && (
                    <div className="flex items-center gap-2 mb-3 p-2 bg-muted/50 rounded border border-border">
                      <SearchableSelect
                        value={selectedWebsiteId}
                        onValueChange={setSelectedWebsiteId}
                        options={unassociatedWebsites.map((w) => ({
                          value: w.id.toString(),
                          label: `${w.name} (${w.url})`,
                        }))}
                        placeholder="Select Website"
                        triggerClassName="h-7 bg-background border-primary/50 text-foreground text-xs flex-1"
                      />
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={handleAddWebsite}
                        disabled={!selectedWebsiteId}
                        className="h-7 w-7 text-success hover:bg-success/10"
                      >
                        <Check className="w-3.5 h-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => setIsAddingWebsite(false)}
                        className="h-7 w-7 text-destructive hover:bg-destructive/10"
                      >
                        <X className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  )}

                  {service.websites.length > 0
                    ? service.websites.map((site) => (
                        <Card
                          key={site.id}
                          onClick={() => {
                            onClose();
                            navigate({
                              to: "/websites",
                              search: { websiteId: site.id },
                            });
                          }}
                          className="group/website bg-card/40 border-border p-3 hover:border-info/30 transition-colors cursor-pointer relative"
                        >
                          <div className="flex justify-between items-start mb-1">
                            <span className="text-[10px] font-bold text-foreground truncate pr-2 group-hover/website:text-info transition-colors flex items-center gap-1">
                              {site.name || "Unnamed Site"}
                              <ArrowUpRight className="w-2.5 h-2.5 opacity-0 group-hover/website:opacity-100 transition-opacity" />
                            </span>
                            <div className="flex items-center gap-2">
                              <Globe className="w-3 h-3 text-info" />
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-4 w-4 text-muted-foreground hover:text-destructive opacity-0 group-hover/website:opacity-100 transition-opacity"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleRemoveWebsite(site.id);
                                }}
                              >
                                <Unlink className="w-3 h-3" />
                              </Button>
                            </div>
                          </div>
                          <div
                            role="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              window.open(
                                ensureAbsoluteUrl(site.url),
                                "_blank",
                              );
                            }}
                            className="text-[9px] text-info/70 hover:text-info/80 hover:underline truncate block font-mono cursor-pointer"
                          >
                            {site.url}
                          </div>
                        </Card>
                      ))
                    : !isAddingWebsite && (
                        <div className="text-center py-8 opacity-20">
                          <Globe className="w-8 h-8 mx-auto mb-2" />
                          <p className="text-[9px] uppercase font-black">
                            No web routes
                          </p>
                        </div>
                      )}
                </div>
              </ScrollArea>
            </DetailTile>
          </div>

          {/* Column 3: Credentials + Dependencies */}
          <div className="space-y-6">
            <DetailTile title="Access Credentials" icon={Shield} noPadding>
              <div className="p-4 space-y-3">
                {service.websites
                  .filter((w) => w.username)
                  .map((site) => (
                    <Card
                      key={site.id}
                      className="bg-card/40 border-border shadow-none py-0 gap-0 overflow-hidden"
                    >
                      <CardHeader className="p-3 pb-1 border-none gap-1 bg-muted/20">
                        <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase">
                          {site.name || "Website"} Login
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="p-3 space-y-2">
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="text-muted-foreground">User</span>
                          <span className="text-foreground font-mono">
                            {site.username}
                          </span>
                        </div>
                        <div className="flex justify-between items-center text-[10px]">
                          <span className="text-muted-foreground">
                            Password
                          </span>
                          <span className="flex items-center">
                            {site.passwordIndex !== undefined &&
                            site.passwordIndex !== null ? (
                              <Link
                                to="/passwords"
                                search={{ highlight: site.passwordIndex }}
                                onClick={(e) => e.stopPropagation()}
                              >
                                <Badge
                                  variant="outline"
                                  className="font-mono text-[10px] font-bold bg-primary/10 text-primary border-primary/30 hover:bg-primary/20 hover:border-primary/50 cursor-pointer transition-colors"
                                >
                                  {site.passwordIndex}
                                </Badge>
                              </Link>
                            ) : (
                              <span className="text-muted-foreground/40 font-mono text-xs font-bold">
                                —
                              </span>
                            )}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                {service.websites.every((w) => !w.username) && (
                  <div className="text-center py-8 opacity-20">
                    <Shield className="w-8 h-8 mx-auto mb-2" />
                    <p className="text-[9px] uppercase font-black">
                      No service keys
                    </p>
                  </div>
                )}
              </div>
            </DetailTile>

            <DetailTile
              title="Dependencies"
              icon={Network}
              noPadding
              headerAction={
                !isAddingDep && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setIsAddingDep(true)}
                    className="h-6 w-6 text-muted-foreground hover:text-primary"
                  >
                    <Plus className="w-3 h-3" />
                  </Button>
                )
              }
            >
              <ScrollArea className="h-[200px] w-full p-4">
                <div className="space-y-2">
                  {isAddingDep && (
                    <div className="flex items-center gap-2 mb-3 p-2 bg-muted/50 rounded border border-border">
                      <SearchableSelect
                        value={selectedDepId}
                        onValueChange={setSelectedDepId}
                        options={availableForDep.map((s) => {
                          const depHost = hosts?.find((h) => h.id === s.hostId);
                          return {
                            value: s.id.toString(),
                            label: `${s.name}${depHost ? ` on ${depHost.hostname || depHost.ip}` : ""}`,
                          };
                        })}
                        placeholder="Select Service"
                        triggerClassName="h-7 bg-background border-primary/50 text-foreground text-xs flex-1"
                      />
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          if (selectedDepId)
                            addDepMutation.mutate(parseInt(selectedDepId));
                        }}
                        disabled={!selectedDepId}
                        className="h-7 w-7 text-success hover:bg-success/10"
                      >
                        <Check className="w-3.5 h-3.5" />
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => setIsAddingDep(false)}
                        className="h-7 w-7 text-destructive hover:bg-destructive/10"
                      >
                        <X className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  )}

                  {service.dependencies.length > 0
                    ? service.dependencies.map((dep) => {
                        const depService = allServices?.find(
                          (s) => s.id === dep.dependsOnId,
                        );
                        const depHost = hosts?.find(
                          (h) => h.id === depService?.hostId,
                        );
                        return (
                          <Card
                            key={dep.dependsOnId}
                            onClick={() => {
                              onClose();
                              navigate({
                                to: "/services",
                                search: { serviceId: dep.dependsOnId },
                              });
                            }}
                            className="group/dep bg-card/40 border-border p-3 hover:border-info/30 transition-colors cursor-pointer relative"
                          >
                            <div className="flex justify-between items-start mb-1">
                              <span className="text-[10px] font-bold text-foreground truncate pr-2 group-hover/dep:text-info transition-colors flex items-center gap-1">
                                {dep.dependsOnName ||
                                  depService?.name ||
                                  `Service #${dep.dependsOnId}`}
                                <ArrowUpRight className="w-2.5 h-2.5 opacity-0 group-hover/dep:opacity-100 transition-opacity" />
                              </span>
                              <div className="flex items-center gap-2">
                                <Zap className="w-3 h-3 text-info" />
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-4 w-4 text-muted-foreground hover:text-destructive opacity-0 group-hover/dep:opacity-100 transition-opacity"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    removeDepMutation.mutate(dep.dependsOnId);
                                  }}
                                >
                                  <Unlink className="w-3 h-3" />
                                </Button>
                              </div>
                            </div>
                            {depHost && (
                              <div className="text-[9px] text-info/70 truncate font-mono">
                                {depHost.hostname || depHost.ip}
                              </div>
                            )}
                          </Card>
                        );
                      })
                    : !isAddingDep && (
                        <div className="text-center py-8 opacity-20">
                          <Network className="w-8 h-8 mx-auto mb-2" />
                          <p className="text-[9px] uppercase font-black">
                            No dependencies
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

function StatusToggle({
  label,
  active,
  onClick,
  icon,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
}) {
  return (
    <div
      onClick={onClick}
      className={cn(
        "flex items-center justify-between p-2 rounded-md border cursor-pointer transition-all",
        active
          ? "bg-success/20 border-success/50 text-success shadow-[0_0_10px_rgba(var(--success),0.05)]"
          : "bg-card/40 border-border text-muted-foreground hover:border-primary/50",
      )}
    >
      <div className="flex items-center gap-2">
        <div
          className={cn(
            "p-1 rounded bg-black/20",
            active ? "text-success" : "text-muted-foreground",
          )}
        >
          {icon}
        </div>
        <span className="text-[10px] font-bold uppercase tracking-wider">
          {label}
        </span>
      </div>
      <div
        className={cn(
          "w-2 h-2 rounded-full",
          active
            ? "bg-success shadow-[0_0_8px_rgba(var(--success),0.8)]"
            : "bg-muted",
        )}
      />
    </div>
  );
}
