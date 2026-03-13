import type { AnyFieldApi } from "@tanstack/react-form";

export function FieldInfo({ field }: { field: AnyFieldApi }) {
  return (
    <>
      {field.state.meta.isTouched && !field.state.meta.isValid ? (
        <p className="text-[10px] font-medium text-destructive mt-1">
          {field.state.meta.errors
            ? field.state.meta.errors
                .map((e: any) => (e?.message ? e.message : String(e)))
                .join(", ")
            : null}
        </p>
      ) : null}
      {field.state.meta.isValidating ? (
        <p className="text-[10px] text-muted-foreground mt-1">Validating...</p>
      ) : null}
    </>
  );
}
