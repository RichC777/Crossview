import raw from "./data/loldrivers-gap.json";

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

export const FEED = raw as GapFeed;

export function coveragePct(s = FEED.stats): number {
  if (!s.samples) return 0;
  return Math.round((1000 * s.hashCovered) / s.samples) / 10;
}
