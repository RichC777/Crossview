import type { ReactNode } from "react";

export function Page({
  title,
  lead,
  children,
}: {
  title: string;
  lead?: string;
  children: ReactNode;
}) {
  return (
    <main className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-2xl font-medium tracking-tight">{title}</h1>
        {lead ? <p className="max-w-3xl text-sm leading-relaxed text-muted">{lead}</p> : null}
      </header>
      {children}
    </main>
  );
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="max-w-3xl rounded-sm border border-line bg-surface px-3 py-2 text-sm text-muted">
      {children}
    </p>
  );
}

export function Panel({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className="space-y-3 rounded-sm border border-line bg-surface p-4">
      {title ? <h2 className="text-sm font-medium tracking-wide">{title}</h2> : null}
      {children}
    </section>
  );
}

export function DataTable({
  headers,
  rows,
}: {
  headers: string[];
  rows: Array<Array<ReactNode>>;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-line text-[11px] uppercase tracking-wider text-faint">
            {headers.map((h) => (
              <th key={h} className="px-2 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-line/70 align-top">
              {row.map((cell, j) => (
                <td key={j} className="px-2 py-2">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="max-h-[32rem] overflow-auto rounded-sm border border-line bg-bg p-3 font-mono text-[12px] leading-relaxed text-fg/90">
      {children}
    </pre>
  );
}
