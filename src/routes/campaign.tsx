import { createFileRoute } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { Notice, Page, Panel } from "@/components/page";

export const Route = createFileRoute("/campaign")({
  component: CampaignPage,
});

function CampaignPage() {
  return (
    <Page
      title="FudModule 3.1"
      lead="Notes for Lazarus FudModule 3.1 (CVE-2026-68820 / Operation Dream Job). Detection notes only — no exploit steps."
    >
      <div className="flex flex-wrap gap-1.5">
        <Badge variant="high">CVE-2026-68820</Badge>
        <Badge variant="mute">data-only</Badge>
      </div>
      <Notice>
        FudModule 3.1 is data-only. A clean SSDT/hook scan plus dead ETW and empty EDR callback
        slots is the hit, not a clean bill of health.
      </Notice>
      <Panel title="What the --fudmodule profile covers">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
          <li>Quick set: process, token, callbacks, ETW, BYOVD names, integrity, loaded drivers.</li>
          <li>Plus minifilters (T12.e), bugcheck callbacks (T12.i), WFP/BFE (T12.b), extra token checks.</li>
          <li>CLI also probes the 94-GUID ETW kill-list from user mode (T15.b).</li>
        </ul>
      </Panel>
      <Panel title="How to hunt">
        <p className="text-sm text-muted">
          On a test-signed lab box:{" "}
          <code className="font-mono text-fg">cvscan.exe --fudmodule</code>. This console does not
          issue IOCTLs or load the driver.
        </p>
      </Panel>
    </Page>
  );
}
