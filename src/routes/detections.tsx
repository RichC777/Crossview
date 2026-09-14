import { createFileRoute } from "@tanstack/react-router";
import { Badge } from "@/components/ui/badge";
import { CodeBlock, Notice, Page, Panel } from "@/components/page";
import { DETECTION_FILES, kindBadgeVariant } from "@/lib/detections-catalog";

export const Route = createFileRoute("/detections")({
  component: DetectionsPage,
});

function DetectionsPage() {
  const present = DETECTION_FILES.filter((f) => f.kind !== "missing");
  const missing = DETECTION_FILES.filter((f) => f.kind === "missing");

  return (
    <Page
      title="Rules"
      lead="Files under windows/detections/. Sysmon, starter Sigma, starter KQL, the curated LOLDrivers CSV, and markdown notes. This page does not talk to the Windows driver."
    >
      <Notice>
        Merge the Sysmon fragment into an existing config. Do not paste it over a production policy
        without a ring. Do not exclude Signed=true on DriverLoad. Sigma and KQL are experimental
        starters, not a tuned production pack.
      </Notice>
      <Panel title="In this tree">
        <ul className="space-y-3 text-sm">
          {present.map((file) => (
            <li key={file.id} className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-accent">{file.path}</span>
                <Badge variant={kindBadgeVariant(file.kind)}>{file.kind}</Badge>
              </div>
              <p className="text-muted">{file.summary}</p>
            </li>
          ))}
        </ul>
      </Panel>
      {missing.length ? (
        <Panel title="Not checked in">
          <ul className="space-y-3 text-sm">
            {missing.map((file) => (
              <li key={file.id} className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs">{file.name}</span>
                  <Badge variant="medium">missing</Badge>
                </div>
                <p className="text-muted">{file.summary}</p>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
      {present.map((file) =>
        file.content ? (
          <Panel key={file.id} title={file.name}>
            <CodeBlock>{file.content.trimEnd()}</CodeBlock>
          </Panel>
        ) : null,
      )}
    </Page>
  );
}
