import { createFileRoute } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { DataTable, Notice, Page, Panel } from "@/components/page";
import { WDAC_STEPS } from "@/lib/lab-content";
import {
  FEED,
  coveragePct,
  rowClassLabel,
  rowKindLabel,
  shortHash,
} from "@/lib/loldrivers-feed";

export const Route = createFileRoute("/policy")({
  component: PolicyPage,
});

function PolicyPage() {
  return (
    <Page
      title="Policy"
      lead="WDAC allow-known-good checklist from windows/detections/wdac-checklist.md, plus the LOLDrivers-vs-VDBL hash gap when a feed exists. This page does not talk to the Windows driver."
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
          <div className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="info">feed present</Badge>
              <Badge variant="mute">curated sample</Badge>
              <span className="font-mono text-xs text-muted">loldrivers-gap.json</span>
            </div>
            {FEED.provenance ? <Notice>{FEED.provenance}</Notice> : null}
            <p className="text-muted">
              Feed as of {FEED.lolAsOf}. VDBL {FEED.vdblVersion}. Hash coverage {coveragePct()}%
              ({FEED.stats.hashCovered}/{FEED.stats.samples} hashed samples). {FEED.stats.gap} gap
              rows. {FEED.stats.nameOnly} name-only.
            </p>
            <p className="font-mono text-xs text-accent">{FEED.rows.length} rows</p>
            <DataTable
              headers={["Name", "Vendor", "Class", "SHA256", "VDBL", "Kind", "Note"]}
              rows={FEED.rows.map((row) => [
                <span className="font-mono text-xs text-accent">{row.n}</span>,
                row.v,
                rowClassLabel(row.c),
                <span className="font-mono text-xs">{shortHash(row.s)}</span>,
                row.h ? "hash" : "—",
                rowKindLabel(row),
                <span className="text-muted">{row.m}</span>,
              ])}
            />
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
