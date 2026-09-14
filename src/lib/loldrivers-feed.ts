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

const EMPTY_STATS: GapFeed["stats"] = {
  drivers: 0,
  samples: 0,
  hashCovered: 0,
  nameOnly: 0,
  gap: 0,
  hvciOk: 0,
  malicious: 0,
  actionable: 0,
  vdblHashTokens: 0,
  vdblNames: 0,
};

export const FEED: GapFeed = {
  available: false,
  reason:
    "src/lib/data/loldrivers-gap.json is not in this tree. The Policy page stays empty until a LOLDrivers-vs-VDBL feed is generated.",
  lolAsOf: "",
  vdblVersion: "",
  vdblPolicyId: "",
  generated: "",
  stats: EMPTY_STATS,
  rows: [],
};

export function coveragePct(s = FEED.stats): number {
  if (!s.samples) return 0;
  return Math.round((1000 * s.hashCovered) / s.samples) / 10;
}
