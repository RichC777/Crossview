import type { ReactNode } from "react";
import { Link, useRouterState } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { Crosshair, ScanSearch, Grid3x3, Skull, Cpu, Terminal, ShieldAlert, ShieldCheck } from "lucide-react";

const NAV = [
  { to: "/", label: "Scanner", icon: ScanSearch },
  { to: "/matrix", label: "Matrix", icon: Grid3x3 },
  { to: "/campaign", label: "FudModule", icon: Skull },
  { to: "/detections", label: "Rules", icon: ShieldAlert },
  { to: "/policy", label: "Policy", icon: ShieldCheck },
  { to: "/package", label: "Driver", icon: Cpu },
  { to: "/cli", label: "CLI", icon: Terminal },
] as const;

export function Shell({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  return (
    <div className="min-h-dvh overflow-x-hidden bg-bg text-fg">
      <header className="sticky top-0 z-30 border-b border-line bg-bg/90 backdrop-blur-sm">
        <div className="mx-auto flex min-w-0 max-w-[1400px] items-center gap-3 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2.5 text-fg no-underline">
            <span className="flex h-8 w-8 items-center justify-center rounded-sm border border-line bg-surface">
              <Crosshair className="h-4 w-4 text-accent" strokeWidth={1.75} />
            </span>
            <span className="leading-tight">
              <span className="block font-sans text-[13px] font-medium tracking-[0.18em]">CROSSVIEW</span>
              <span className="hidden font-mono text-[10px] uppercase tracking-wider text-muted sm:block">
                Kernel integrity scanner
              </span>
            </span>
          </Link>
          <nav className="ml-auto flex min-w-0 items-center gap-0.5 overflow-x-auto">
            {NAV.map((item) => {
              const active = pathname === item.to;
              const Icon = item.icon;
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    "flex h-11 items-center gap-1.5 rounded-sm px-2.5 text-xs no-underline sm:px-3",
                    active ? "bg-surface-2 text-fg" : "text-muted hover:text-fg",
                  )}
                >
                  <Icon className="h-3.5 w-3.5" strokeWidth={1.75} />
                  <span className="hidden sm:inline">{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>
      </header>
      <div className="mx-auto min-w-0 max-w-[1400px] px-4 py-6 sm:px-6 sm:py-8">{children}</div>
    </div>
  );
}
