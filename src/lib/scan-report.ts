import sample from "../fixtures/cvscan-sample-report.json";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "CLEAN"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Finding = {
  severity: Severity;
  module: string;
  technique: string;
  title: string;
  detail: string;
  evidence: string;
};

export type ScanReport = {
  version: string;
  build: number;
  driverReady: number;
  findings: Finding[];
};

export const SAMPLE_REPORT = sample as ScanReport;

export type ParseResult = { ok: true; report: ScanReport } | { ok: false; error: string };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export function parseScanReport(text: string): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    return { ok: false, error: `Not valid JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!isRecord(raw) || !Array.isArray(raw.findings)) {
    return { ok: false, error: "Expected an object with a findings array (cvscan --json shape)." };
  }
  const findings: Finding[] = [];
  for (const [i, f] of raw.findings.entries()) {
    if (!isRecord(f) || !isSeverity(f.severity)) {
      return {
        ok: false,
        error: `findings[${i}].severity must be one of ${SEVERITIES.join(", ")}.`,
      };
    }
    findings.push({
      severity: f.severity,
      module: str(f.module),
      technique: str(f.technique),
      title: str(f.title),
      detail: str(f.detail),
      evidence: str(f.evidence),
    });
  }
  return {
    ok: true,
    report: {
      version: str(raw.version),
      build: typeof raw.build === "number" ? raw.build : 0,
      driverReady: typeof raw.driverReady === "number" ? raw.driverReady : 0,
      findings,
    },
  };
}

export function severityBadgeVariant(
  s: Severity,
): "critical" | "high" | "medium" | "low" | "info" | "clean" {
  switch (s) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    case "INFO":
      return "info";
    case "CLEAN":
      return "clean";
    default: {
      const _exhaustive: never = s;
      return _exhaustive;
    }
  }
}

export function modulesOf(findings: Finding[]): string[] {
  return [...new Set(findings.map((f) => f.module))].sort();
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function filterFindings(
  findings: Finding[],
  severities: ReadonlySet<Severity>,
  module: string | null,
): Finding[] {
  return findings.filter(
    (f) => severities.has(f.severity) && (module === null || f.module === module),
  );
}

export function cliExitCode(findings: Finding[]): 0 | 1 {
  return findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH") ? 1 : 0;
}
