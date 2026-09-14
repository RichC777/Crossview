import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { DataTable, Panel } from "@/components/page";
import { cn } from "@/lib/utils";
import {
  SEVERITIES,
  cliExitCode,
  countBySeverity,
  filterFindings,
  modulesOf,
  severityBadgeVariant,
  type ScanReport,
  type Severity,
} from "@/lib/scan-report";

export function ScanReportView({ report }: { report: ScanReport }) {
  const [severities, setSeverities] = useState<ReadonlySet<Severity>>(new Set(SEVERITIES));
  const [module, setModule] = useState<string | null>(null);

  const counts = countBySeverity(report.findings);
  const modules = modulesOf(report.findings);
  const shown = filterFindings(report.findings, severities, module);

  function toggleSeverity(s: Severity) {
    const next = new Set(severities);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSeverities(next);
  }

  return (
    <>
      <Panel title="Report header">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs text-muted">
          <span>version={report.version || "?"}</span>
          <span>build={report.build || "?"}</span>
          <span>driverReady={report.driverReady}</span>
          <span>findings={report.findings.length}</span>
          <span className={cliExitCode(report.findings) ? "text-high" : "text-ok"}>
            cvscan exit={cliExitCode(report.findings)}
          </span>
        </div>
      </Panel>
      <Panel title="Findings">
        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITIES.map((s) => {
            const on = severities.has(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => toggleSeverity(s)}
                className={cn(
                  "rounded-sm border px-1 py-0.5",
                  on ? "border-line" : "border-transparent opacity-40 hover:opacity-70",
                )}
              >
                <Badge variant={severityBadgeVariant(s)}>
                  {s} {counts[s]}
                </Badge>
              </button>
            );
          })}
          <label className="ml-auto flex items-center gap-2 text-xs text-muted">
            module
            <select
              value={module ?? ""}
              onChange={(e) => setModule(e.target.value || null)}
              className="rounded-sm border border-line bg-bg px-2 py-1 font-mono text-xs text-fg"
            >
              <option value="">all</option>
              {modules.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="font-mono text-xs text-accent">
          {shown.length} of {report.findings.length} findings
        </p>
        <DataTable
          headers={["Severity", "Module", "Technique", "Finding", "Evidence"]}
          rows={shown.map((f) => [
            <Badge variant={severityBadgeVariant(f.severity)}>{f.severity}</Badge>,
            <span className="font-mono text-xs">{f.module}</span>,
            <span className="font-mono text-xs text-accent">{f.technique}</span>,
            <span className="block max-w-xl space-y-1">
              <span className="block">{f.title}</span>
              <span className="block text-xs text-muted">{f.detail}</span>
            </span>,
            <span className="font-mono text-xs text-muted">{f.evidence || "—"}</span>,
          ])}
        />
      </Panel>
    </>
  );
}
