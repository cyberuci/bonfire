import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, X, Edit2, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { DetailTile } from "./DetailTile";

interface PortListProps<T> {
  title: string;
  items: T[];
  getPort: (item: T) => number;
  onAdd: (port: number) => void;
  onDelete: (item: T) => void;
  onViewClick?: (item: T) => void;
  viewBadgeVariant?: (item: T) => string;
  emptyMessage?: string;
  description?: string;
  icon: any;
}

export function PortList<T>({
  title,
  items,
  getPort,
  onAdd,
  onDelete,
  onViewClick,
  viewBadgeVariant,
  emptyMessage = "No ports configured",
  description,
  icon,
}: PortListProps<T>) {
  const [isEditing, setIsEditing] = useState(false);
  const [newPort, setNewPort] = useState("");

  const handleAdd = () => {
    const port = parseInt(newPort);
    if (!isNaN(port) && port > 0 && port < 65536) {
      onAdd(port);
      setNewPort("");
    }
  };

  return (
    <DetailTile
      title={title}
      icon={icon}
      headerAction={
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setIsEditing(!isEditing)}
          className={cn(
            "h-6 w-6 transition-colors",
            isEditing
              ? "text-primary bg-primary/10"
              : "text-muted-foreground hover:text-primary",
          )}
        >
          {isEditing ? (
            <Check className="w-3 h-3" />
          ) : (
            <Edit2 className="w-3 h-3" />
          )}
        </Button>
      }
    >
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2 items-center">
          {items.length > 0
            ? items
                .sort((a, b) => getPort(a) - getPort(b))
                .map((item) => {
                  const port = getPort(item);
                  return (
                    <Badge
                      key={port}
                      variant="outline"
                      onClick={() =>
                        isEditing
                          ? onDelete(item)
                          : onViewClick && onViewClick(item)
                      }
                      className={cn(
                        "font-mono text-[10px] py-1 px-2 border justify-center transition-all select-none relative group/badge",
                        isEditing
                          ? "cursor-pointer bg-muted text-muted-foreground border-border hover:border-destructive hover:text-destructive pr-6"
                          : "cursor-pointer",
                        !isEditing && viewBadgeVariant
                          ? viewBadgeVariant(item)
                          : !isEditing &&
                              "bg-muted text-muted-foreground border-border",
                      )}
                    >
                      {port}
                      {isEditing && (
                        <span className="absolute right-1 top-1/2 -translate-y-1/2 opacity-50 group-hover/badge:opacity-100">
                          <X className="w-3 h-3" />
                        </span>
                      )}
                    </Badge>
                  );
                })
            : !isEditing && (
                <span className="text-muted-foreground text-[10px] italic w-full text-center py-2 bg-muted/30 rounded">
                  {emptyMessage}
                </span>
              )}

          {isEditing && (
            <div className="flex items-center gap-1">
              <Input
                autoFocus
                placeholder="Port"
                value={newPort}
                onChange={(e) => setNewPort(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAdd();
                }}
                className="h-6 w-16 text-[10px] font-mono px-2 bg-background border-primary/50 focus-visible:ring-primary/50"
              />
              <Button
                size="icon"
                variant="ghost"
                onClick={handleAdd}
                className="h-6 w-6 text-primary hover:bg-primary/10"
              >
                <Plus className="w-3 h-3" />
              </Button>
            </div>
          )}
        </div>
        {description && (
          <p className="text-[10px] text-muted-foreground text-center">
            {isEditing ? "Add ports or click to remove." : description}
          </p>
        )}
      </div>
    </DetailTile>
  );
}
