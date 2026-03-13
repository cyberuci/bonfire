import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Check, X, Edit2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { SearchableSelect } from "@/components/ui/searchable-select";

export interface EditableFieldProps {
  label: string;
  value: string;
  onSave: (newValue: string) => void;
  isEditing: boolean;
  setIsEditing: (editing: boolean) => void;
  fontMono?: boolean;
  hideLabel?: boolean;
}

export function EditableField({
  label,
  value,
  onSave,
  isEditing,
  setIsEditing,
  fontMono = false,
  hideLabel = false,
}: EditableFieldProps) {
  const [tempValue, setTempValue] = useState(value);

  useEffect(() => {
    setTempValue(value);
  }, [value, isEditing]);

  const handleSave = () => {
    onSave(tempValue);
    setIsEditing(false);
  };

  const handleCancel = () => {
    setTempValue(value);
    setIsEditing(false);
  };

  return (
    <div
      className={cn(
        "flex items-center group/field py-1 w-full",
        !hideLabel ? "justify-between" : "justify-start",
      )}
    >
      {!hideLabel && (
        <span className="text-muted-foreground text-[11px] font-medium uppercase tracking-tight">
          {label}
        </span>
      )}
      <div className={cn("flex items-center gap-2", hideLabel && "flex-1")}>
        {isEditing ? (
          <div className="flex items-center gap-1 w-full">
            <Input
              autoFocus
              className={cn(
                "h-7 py-1 text-xs bg-background border-primary/50 focus-visible:ring-primary/50 text-foreground",
                fontMono && "font-mono",
                hideLabel ? "flex-1 min-w-[150px]" : "w-40",
              )}
              value={tempValue}
              onChange={(e) => setTempValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSave();
                if (e.key === "Escape") handleCancel();
              }}
            />
            <button
              onClick={handleSave}
              className="p-1 text-success hover:bg-success/10 rounded transition-colors flex-shrink-0"
            >
              <Check className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleCancel}
              className="p-1 text-destructive hover:bg-destructive/10 rounded transition-colors flex-shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : (
          <div
            className={cn("flex items-center gap-1.5", hideLabel && "w-full")}
          >
            <span
              className={cn(
                "text-foreground text-xs",
                fontMono && "font-mono",
                hideLabel && "truncate",
              )}
            >
              {value || "Unknown"}
            </span>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsEditing(true)}
              className="h-5 w-5 text-muted-foreground hover:text-primary opacity-0 group-hover/field:opacity-100 transition-all flex-shrink-0"
            >
              <Edit2 className="w-2.5 h-2.5" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export interface EditableEnumFieldProps {
  label: string;
  value: string;
  options: string[];
  onSave: (newValue: string) => void;
  isEditing: boolean;
  setIsEditing: (editing: boolean) => void;
  valueClassName?: string;
  renderValue?: (value: string) => React.ReactNode;
}

export function EditableEnumField({
  label,
  value,
  options,
  onSave,
  isEditing,
  setIsEditing,
  valueClassName,
  renderValue,
}: EditableEnumFieldProps) {
  return (
    <div className="flex justify-between items-center group/field py-1">
      <span className="text-muted-foreground text-[11px] font-medium uppercase tracking-tight">
        {label}
      </span>
      <div className="flex items-center gap-2">
        {isEditing ? (
          <div className="flex items-center gap-1">
            <SearchableSelect
              value={value}
              onValueChange={(val) => {
                onSave(val);
                setIsEditing(false);
              }}
              options={options.map((opt) => ({
                value: opt,
                label: opt,
              }))}
              placeholder="Select"
              triggerClassName="h-7 py-0 bg-background border-primary/50 text-foreground w-[100px] text-xs"
            />
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setIsEditing(false)}
              className="h-7 w-7 text-destructive hover:bg-destructive/10"
            >
              <X className="w-3.5 h-3.5" />
            </Button>
          </div>
        ) : (
          <div className="flex items-center gap-1.5">
            <span className={cn("text-foreground text-xs", valueClassName)}>
              {renderValue ? renderValue(value) : value || "Unknown"}
            </span>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setIsEditing(true)}
              className="h-5 w-5 text-muted-foreground hover:text-primary opacity-0 group-hover/field:opacity-100 transition-all"
            >
              <Edit2 className="w-2.5 h-2.5" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
