import { useState } from "react";
import { useMutation, useQueryClient, useQuery } from "@tanstack/react-query";
import { client } from "@/lib/client";
import { Website } from "@/gen/northstar_pb";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Globe,
  ExternalLink,
  User,
  Trash2,
  Edit2,
  X,
  Eye,
  EyeOff,
  Server,
  ArrowUpRight,
  Shield,
  ShieldOff,
  CheckCircle2,
  Circle,
} from "lucide-react";
import { cn, ensureAbsoluteUrl } from "@/lib/utils";
import { useNavigate, Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { SearchableSelect } from "@/components/ui/searchable-select";
import { DetailTile } from "./DetailTile";
import { EditableField, EditableEnumField } from "./EditableField";
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

interface WebsiteDetailModalProps {
  website: Website;
  onClose: () => void;
}

export function WebsiteDetailModal({
  website,
  onClose,
}: WebsiteDetailModalProps) {
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [editingField, setEditingField] = useState<string | null>(null);
  const [isEditingService, setIsEditingService] = useState(false);
  const [enumerated, setEnumerated] = useState(website.enumerated);
  const navigate = useNavigate();

  const queryClient = useQueryClient();

  const { data: services } = useQuery({
    queryKey: ["services"],
    queryFn: async () => {
      const response = await client.listServices({});
      return response.services;
    },
  });

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
        enumerated: updatedWebsite.enumerated ?? enumerated,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["websites"] });
      setIsEditingService(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      await client.deleteWebsite({ id: website.id });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["websites"] });
      onClose();
    },
  });

  const handleUpdate = (field: keyof Website, value: any) => {
    if (field === "enumerated") setEnumerated(value);
    mutation.mutate({ [field]: value });
  };

  const associatedService = services?.find((s) => s.id === website.serviceId);

  return (
    <Dialog open={true} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-[95vw] sm:max-w-3xl bg-background border-border text-foreground shadow-2xl shadow-black p-0 overflow-hidden">
        <DialogHeader className="border-b border-border px-6 py-4 bg-muted/40">
          <DialogTitle className="text-xl font-bold flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
                <Globe className="w-5 h-5" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-bold text-muted-foreground uppercase tracking-widest leading-none mb-1">
                  Website Details
                </span>
                <span className="text-xl text-foreground flex items-center gap-2">
                  {website.name}
                  <div
                    role="button"
                    onClick={() =>
                      window.open(ensureAbsoluteUrl(website.url), "_blank")
                    }
                    className="text-muted-foreground hover:text-primary transition-colors cursor-pointer"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </div>
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
                    <AlertDialogTitle>Delete {website.name}?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This action cannot be undone. This will permanently delete
                      the website and its credentials.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                      onClick={() => deleteMutation.mutate()}
                      className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
                    >
                      Delete Website
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>

              <Badge
                variant="outline"
                onClick={() => handleUpdate("enumerated", !enumerated)}
                className={cn(
                  "cursor-pointer flex items-center gap-1.5 px-3 py-1 rounded-md text-[10px] font-black uppercase tracking-wider transition-all border-2 select-none",
                  enumerated
                    ? "bg-success/20 text-success border-success/50 hover:bg-success/10"
                    : "bg-warning/20 text-warning border-warning/50 hover:bg-warning/10",
                )}
              >
                {enumerated ? (
                  <CheckCircle2 className="w-3 h-3" />
                ) : (
                  <Circle className="w-3 h-3" />
                )}
                {enumerated ? "Complete" : "In Progress"}
              </Badge>
            </div>
          </DialogTitle>
        </DialogHeader>

        <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[80vh] overflow-y-auto custom-scrollbar">
          {/* Column 1: General Info */}
          <div className="space-y-6">
            <DetailTile title="General Information" icon={Globe}>
              <div className="space-y-0.5">
                <EditableField
                  label="Name"
                  value={website.name}
                  isEditing={editingField === "name"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "name" : null)
                  }
                  onSave={(val) => handleUpdate("name", val)}
                />
                <EditableField
                  label="URL"
                  value={website.url}
                  isEditing={editingField === "url"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "url" : null)
                  }
                  onSave={(val) => handleUpdate("url", val)}
                />
              </div>
            </DetailTile>

            <DetailTile
              title="Associated Service"
              icon={Server}
              noPadding
              headerAction={
                !isEditingService && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setIsEditingService(true)}
                    className="h-6 w-6 text-muted-foreground hover:text-primary"
                  >
                    <Edit2 className="w-3 h-3" />
                  </Button>
                )
              }
            >
              <div className="p-4">
                {isEditingService ? (
                  <div className="flex items-center gap-2">
                    <SearchableSelect
                      value={website.serviceId.toString()}
                      onValueChange={(val) => {
                        handleUpdate("serviceId", parseInt(val));
                        setIsEditingService(false);
                      }}
                      options={[
                        { value: "0", label: "None" },
                        ...(services?.map((s) => ({
                          value: s.id.toString(),
                          label: `${s.name} (${s.technology})`,
                        })) ?? []),
                      ]}
                      placeholder="Select Service"
                      triggerClassName="h-8 bg-background border-primary/50 text-foreground text-xs"
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => setIsEditingService(false)}
                      className="h-8 w-8 text-destructive hover:bg-destructive/10"
                    >
                      <X className="w-4 h-4" />
                    </Button>
                  </div>
                ) : associatedService ? (
                  <Card
                    onClick={() => {
                      onClose();
                      navigate({
                        to: "/services",
                        search: { serviceId: associatedService.id },
                      });
                    }}
                    className="group/service bg-card/40 border-border hover:border-primary/30 transition-colors shadow-none py-0 gap-0 cursor-pointer"
                  >
                    <CardHeader className="p-3 pb-1 border-none gap-1">
                      <div className="flex justify-between items-start">
                        <h5 className="font-bold text-foreground text-xs tracking-tight group-hover/service:text-primary transition-colors flex items-center gap-1.5">
                          {associatedService.name}
                          <ArrowUpRight className="w-2.5 h-2.5 opacity-0 group-hover/service:opacity-100 transition-opacity" />
                        </h5>
                        {associatedService.scored && (
                          <Badge
                            variant="outline"
                            className="bg-primary/10 text-primary border-primary/20 text-[8px] px-1 py-0 font-black uppercase tracking-tighter"
                          >
                            Scored
                          </Badge>
                        )}
                      </div>
                      <p className="text-[10px] text-muted-foreground leading-none">
                        {associatedService.technology}
                      </p>
                    </CardHeader>
                    <CardContent className="p-3 pt-2">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={cn(
                            "flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[9px] font-black uppercase tracking-wider border",
                            !associatedService.disabled
                              ? "bg-success/20 text-success border-success/50"
                              : "bg-destructive/20 text-destructive border-destructive/50",
                          )}
                        >
                          {associatedService.disabled ? (
                            <ShieldOff className="w-2.5 h-2.5" />
                          ) : (
                            <Shield className="w-2.5 h-2.5" />
                          )}
                          {associatedService.disabled ? "Offline" : "Active"}
                        </Badge>
                      </div>
                    </CardContent>
                  </Card>
                ) : (
                  <div className="text-center py-4 opacity-50">
                    <p className="text-[10px] text-muted-foreground italic">
                      No service associated
                    </p>
                  </div>
                )}
              </div>
            </DetailTile>
          </div>

          {/* Column 2: Credentials */}
          <div className="space-y-6">
            <DetailTile title="Credentials" icon={User}>
              <div className="space-y-3">
                <EditableField
                  label="Username"
                  value={website.username}
                  isEditing={editingField === "username"}
                  setIsEditing={(editing) =>
                    setEditingField(editing ? "username" : null)
                  }
                  onSave={(val) => handleUpdate("username", val)}
                />

                <EditableEnumField
                  label="Password"
                  value={
                    website.passwordIndex !== undefined &&
                    website.passwordIndex !== null
                      ? `${website.passwordIndex}`
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

                <div className="flex justify-between items-center group/field py-1">
                  <span className="text-muted-foreground text-[11px] font-medium uppercase tracking-tight">
                    Old Password
                  </span>
                  <div className="flex items-center gap-2">
                    {editingField === "oldPassword" ? (
                      <div className="flex items-center gap-1">
                        <Input
                          autoFocus
                          className="h-7 bg-background border-primary/50 font-mono text-[10px] focus-visible:ring-primary/50 w-32 text-foreground"
                          defaultValue={website.oldPassword}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              handleUpdate(
                                "oldPassword",
                                (e.target as HTMLInputElement).value,
                              );
                              setEditingField(null);
                            }
                            if (e.key === "Escape") setEditingField(null);
                          }}
                          onBlur={(e) => {
                            handleUpdate("oldPassword", e.target.value);
                            setEditingField(null);
                          }}
                        />
                      </div>
                    ) : (
                      <div className="flex items-center gap-1">
                        <span className="text-foreground font-mono text-xs mr-1 tracking-widest">
                          {showOldPassword
                            ? website.oldPassword
                            : "••••••••••••"}
                        </span>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setShowOldPassword(!showOldPassword)}
                          className="h-6 w-6 text-muted-foreground hover:text-primary hover:bg-muted"
                        >
                          {showOldPassword ? (
                            <EyeOff className="w-3 h-3" />
                          ) : (
                            <Eye className="w-3 h-3" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setEditingField("oldPassword")}
                          className="h-6 w-6 text-muted-foreground hover:text-primary opacity-0 group-hover/field:opacity-100 transition-all"
                        >
                          <Edit2 className="w-2.5 h-2.5" />
                        </Button>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </DetailTile>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
