import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
  {
    variants: {
      variant: {
        critical: "bg-critical/15 text-critical",
        high: "bg-high/15 text-high",
        medium: "bg-medium/15 text-medium",
        low: "bg-low/15 text-low",
        info: "bg-accent/12 text-accent",
        clean: "bg-ok/15 text-ok",
        mute: "bg-surface-2 text-muted",
      },
    },
    defaultVariants: { variant: "mute" },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
