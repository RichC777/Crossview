import { createFileRoute } from "@tanstack/react-router";
import { DataTable, Notice, Page, Panel } from "@/components/page";
import { CLI_FLAGS } from "@/lib/lab-content";

export const Route = createFileRoute("/cli")({
  component: CliPage,
});

function CliPage() {
  return (
    <Page
      title="CLI"
      lead="cvscan 1.0 flags from windows/cli/cvscan.c. Detection-only. SeLoadDriverPrivilege is required for Ring-0 modules."
    >
      <Notice>
        <code className="font-mono text-fg">cvscan.exe --no-driver</code> stays in user-mode views.
        The browser still does not invoke the CLI.
      </Notice>
      <Panel title="Options">
        <DataTable
          headers={["Flag", "Meaning"]}
          rows={CLI_FLAGS.map((row) => [
            <span className="font-mono text-xs text-accent">{row.flag}</span>,
            <span className="text-muted">{row.detail}</span>,
          ])}
        />
      </Panel>
      <Panel title="Examples">
        <ul className="space-y-1 font-mono text-xs text-muted">
          <li>cvscan.exe --fudmodule</li>
          <li>cvscan.exe --full --json --out report.json</li>
          <li>cvscan.exe --quick --no-driver</li>
        </ul>
      </Panel>
    </Page>
  );
}
