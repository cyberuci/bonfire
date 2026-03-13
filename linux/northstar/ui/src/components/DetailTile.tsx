import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export interface DetailTileProps {
  title: string;
  icon: any;
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
  headerAction?: React.ReactNode;
}

export function DetailTile({
  title,
  icon: Icon,
  children,
  className = "",
  noPadding = false,
  headerAction,
}: DetailTileProps) {
  return (
    <Card
      className={cn(
        "bg-card/50 border-border overflow-hidden flex flex-col gap-0 py-0",
        className,
      )}
    >
      <CardHeader className="py-2.5 px-4 bg-muted/40 border-b border-border flex-row items-center justify-between space-y-0 flex-none">
        <div className="flex items-center gap-2">
          <Icon className="w-3.5 h-3.5 text-primary shrink-0" />
          <CardTitle className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            {title}
          </CardTitle>
        </div>
        {headerAction}
      </CardHeader>
      <CardContent
        className={cn(
          "flex-1 min-h-0",
          noPadding ? "p-0 flex flex-col" : "pt-4 px-4 pb-4",
        )}
      >
        {children}
      </CardContent>
    </Card>
  );
}
