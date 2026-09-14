import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { Notice, Page, Panel } from "@/components/page";
import { ScanReportView } from "@/components/scan-report-view";
import { SAMPLE_REPORT, parseScanReport, type ScanReport } from "@/lib/scan-report";

export const Route = createFileRoute("/")({
  component: ScannerPage,
});

function ScannerPage() {
  const [pasted, setPasted] = useState<ScanReport | null>(null);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);

  const report = pasted ?? SAMPLE_REPORT;

  function loadPasted() {
    const result = parseScanReport(text);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setError(null);
    setPasted(result.report);
  }

  function resetToSample() {
    setPasted(null);
    setText("");
    setError(null);
  }

  return (
    <Page
      title="Scanner"
      lead="Lab-report view of cvscan --full --json output. This page does not run a scan and does not talk to crossview.sys."
    >
      <div className="flex flex-wrap items-center gap-1.5">
        {pasted ? (
          <Badge variant="info">pasted report</Badge>
        ) : (
          <Badge variant="medium">sample data</Badge>
        )}
        <Badge variant="mute">not live</Badge>
        <Badge variant="mute">no ring-0</Badge>
        <span className="font-mono text-xs text-muted">
          {pasted ? "parsed in this tab only" : "src/fixtures/cvscan-sample-report.json"}
        </span>
      </div>
      <Notice>
        {pasted
          ? "Showing a report you pasted. It stays in this browser tab; nothing is uploaded."
          : "Checked-in sample findings shaped like the CLI JSON. Nothing here was collected from this machine."}{" "}
        Ring-0 walks happen on a test-signed Windows box via{" "}
        <code className="font-mono text-fg">cvscan.exe</code>, not from the browser.
      </Notice>
      <ScanReportView key={pasted ? "pasted" : "sample"} report={report} />
      <Panel title="Load your own report.json">
        <p className="text-sm text-muted">
          Paste the output of{" "}
          <code className="font-mono text-fg">cvscan.exe --full --json --out report.json</code>.
          Parsed client-side; no backend.
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={6}
          placeholder='{"version":"1.0","build":26200,"driverReady":1,"findings":[...]}'
          className="w-full rounded-sm border border-line bg-bg p-2 font-mono text-xs text-fg placeholder:text-faint"
        />
        {error ? <p className="text-xs text-high">{error}</p> : null}
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={loadPasted}
            disabled={!text.trim()}
            className="rounded-sm border border-line bg-surface-2 px-3 py-1.5 text-xs text-fg disabled:opacity-40"
          >
            Load report
          </button>
          <button
            type="button"
            onClick={resetToSample}
            disabled={!pasted && !text}
            className="rounded-sm border border-line px-3 py-1.5 text-xs text-muted hover:text-fg disabled:opacity-40"
          >
            Reset to sample
          </button>
        </div>
      </Panel>
      <Panel title="How to run a real scan">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
          <li>
            Build and test-sign on Windows. See <Link to="/package">Driver / package notes</Link>.
          </li>
          <li>
            <code className="font-mono text-fg">cvscan.exe --fudmodule</code> or{" "}
            <code className="font-mono text-fg">--full --json --out report.json</code>. Flags are
            listed on the <Link to="/cli">CLI</Link> page. Module coverage is on the{" "}
            <Link to="/matrix">Matrix</Link>.
          </li>
          <li>
            SIEM fragments live under <Link to="/detections">Rules</Link>. WDAC notes are on{" "}
            <Link to="/policy">Policy</Link>.
          </li>
        </ol>
      </Panel>
    </Page>
  );
}
