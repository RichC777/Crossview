import { createFileRoute, Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { DataTable, Notice, Page, Panel } from "@/components/page";
import { SCANNER_MODULES } from "@/lib/lab-content";

export const Route = createFileRoute("/")({
  component: ScannerPage,
});

function ScannerPage() {
  return (
    <Page
      title="Scanner"
      lead="Fixture notes for the Windows kernel-integrity scanner. This page does not run a scan and does not talk to crossview.sys."
    >
      <Notice>
        Detection-only lab console. Ring-0 walks happen on a test-signed Windows box via{" "}
        <code className="font-mono text-fg">cvscan.exe</code>, not from the browser.
      </Notice>
      <Panel title="What the Windows scanner looks for">
        <DataTable
          headers={["Module", "Techniques", "Note"]}
          rows={SCANNER_MODULES.map((row) => [
            row.module,
            <span className="font-mono text-xs text-accent">{row.techniques}</span>,
            <span className="text-muted">{row.note}</span>,
          ])}
        />
      </Panel>
      <Panel title="How to run a real scan">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
          <li>
            Build and test-sign on Windows. See <Link to="/package">Driver / package notes</Link>.
          </li>
          <li>
            <code className="font-mono text-fg">cvscan.exe --fudmodule</code> or{" "}
            <code className="font-mono text-fg">--full --json --out report.json</code>. Flags are
            listed on the <Link to="/cli">CLI</Link> page.
          </li>
          <li>
            SIEM fragments live under <Link to="/detections">Rules</Link>. WDAC notes are on{" "}
            <Link to="/policy">Policy</Link>.
          </li>
        </ol>
        <div className="flex flex-wrap gap-1.5 pt-2">
          <Badge variant="info">docs only</Badge>
          <Badge variant="mute">no driver bridge</Badge>
        </div>
      </Panel>
    </Page>
  );
}
