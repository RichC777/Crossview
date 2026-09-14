import { createFileRoute } from "@tanstack/react-router";
import { DataTable, Page, Panel } from "@/components/page";
import { SCANNER_MODULES } from "@/lib/lab-content";

export const Route = createFileRoute("/matrix")({
  component: MatrixPage,
});

function MatrixPage() {
  return (
    <Page
      title="Technique matrix"
      lead="Coverage map from windows/README.md. IDs are the lab technique tags the driver and CLI already emit."
    >
      <Panel>
        <DataTable
          headers={["Module", "Techniques", "Signal"]}
          rows={SCANNER_MODULES.map((row) => [
            row.module,
            <span className="font-mono text-xs text-accent">{row.techniques}</span>,
            <span className="text-muted">{row.note}</span>,
          ])}
        />
      </Panel>
    </Page>
  );
}
