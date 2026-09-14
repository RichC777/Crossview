import raw from "../../windows/detections/loldrivers-gap.json";

export type GapRow = {
  n: string;
  v: string;
  c: "m" | "v";
  s: string;
  a: string;
  h: boolean;
  k: "g" | "n";
  m: string;
};

export type GapFeed = {
  available: boolean;
  reason?: string;
  provenance?: string;
  lolAsOf: string;
  vdblVersion: string;
  vdblPolicyId: string;
  generated: string;
  stats: {
    drivers: number;
    samples: number;
    hashCovered: number;
    nameOnly: number;
    gap: number;
    hvciOk: number;
    malicious: number;
    actionable: number;
    vdblHashTokens: number;
    vdblNames: number;
  };
  rows: GapRow[];
};

const parsed = raw as GapFeed;

export const FEED: GapFeed = {
  ...parsed,
  available: parsed.rows.length > 0,
  reason:
    parsed.reason ??
    (parsed.rows.length
      ? undefined
      : "loldrivers-gap.json has no rows. Policy shows the empty hash-gap state."),
};

export function coveragePct(s = FEED.stats): number {
  if (!s.samples) return 0;
  return Math.round((1000 * s.hashCovered) / s.samples) / 10;
}

export function rowClassLabel(c: GapRow["c"]): string {
  switch (c) {
    case "m":
      return "malicious";
    case "v":
      return "vulnerable";
    default: {
      const _exhaustive: never = c;
      return _exhaustive;
    }
  }
}

export function rowKindLabel(row: GapRow): string {
  switch (row.k) {
    case "n":
      return "name-only";
    case "g":
      return row.h ? "hash covered" : "hash gap";
    default: {
      const _exhaustive: never = row.k;
      return _exhaustive;
    }
  }
}

export function shortHash(hex: string): string {
  if (!hex) return "—";
  if (hex.length <= 16) return hex;
  return `${hex.slice(0, 8)}…${hex.slice(-6)}`;
}
