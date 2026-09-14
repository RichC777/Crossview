import { createFileRoute } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { Notice, Page, Panel } from "@/components/page";
import { WDAC_STEPS } from "@/lib/lab-content";
import { FEED, coveragePct } from "@/lib/loldrivers-feed";

export const Route = createFileRoute("/policy")({
  component: PolicyPage,
});

function PolicyPage() {
  return (
    <Page
      title="Policy"
      lead="WDAC allow-known-good checklist from windows/detections/wdac-checklist.md, plus the LOLDrivers-vs-VDBL hash gap when a feed exists."
    >
      <Panel title="WDAC order">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-muted">
          {WDAC_STEPS.map((step) => (
            <li key={step}>{step}</li>
          ))}
        </ol>
      </Panel>
      <Panel title="LOLDrivers hash gap">
        {FEED.available ? (
          <div className="space-y-2 text-sm">
            <p className="text-muted">
              Feed as of {FEED.lolAsOf}. VDBL {FEED.vdblVersion}. Hash coverage{" "}
              {coveragePct()}%.
            </p>
            <p className="font-mono text-xs text-accent">{FEED.rows.length} rows</p>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="medium">no feed</Badge>
              <span className="font-mono text-xs text-muted">loldrivers-gap.json</span>
            </div>
            <Notice>{FEED.reason}</Notice>
          </div>
        )}
      </Panel>
    </Page>
  );
}
