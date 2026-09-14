import detectionsReadme from "../../windows/detections/README.md?raw";
import wdacChecklist from "../../windows/detections/wdac-checklist.md?raw";
import sysmonXml from "../../windows/detections/sysmon-crossview.xml?raw";
import sigmaYml from "../../windows/detections/crossview-byovd-sigma.yml?raw";
import kql from "../../windows/detections/crossview-byovd.kql?raw";
import gapCsv from "../../windows/detections/loldrivers-gap.csv?raw";

export type DetectionKind = "sysmon" | "markdown" | "sigma" | "kql" | "csv" | "missing";

export type DetectionFile = {
  id: string;
  name: string;
  path: string;
  kind: DetectionKind;
  summary: string;
  content?: string;
};

export const DETECTION_FILES: DetectionFile[] = [
  {
    id: "readme",
    name: "README.md",
    path: "windows/detections/README.md",
    kind: "markdown",
    summary: "BYOVD SIEM pack overview, enablement order, and tuning notes.",
    content: detectionsReadme,
  },
  {
    id: "sysmon",
    name: "sysmon-crossview.xml",
    path: "windows/detections/sysmon-crossview.xml",
    kind: "sysmon",
    summary:
      "Sysmon fragment: DriverLoad (signed included), PPL/EDR death, LSASS access, sc/pnputil/clock-tamper process create.",
    content: sysmonXml,
  },
  {
    id: "sigma",
    name: "crossview-byovd-sigma.yml",
    path: "windows/detections/crossview-byovd-sigma.yml",
    kind: "sigma",
    summary:
      "Starter Sigma (experimental): Code Integrity 3076/3077, SCM 7045 from user-writable paths, LOLDrivers-name DriverLoad, PPL death, LSASS access, 4616 clock tamper.",
    content: sigmaYml,
  },
  {
    id: "kql",
    name: "crossview-byovd.kql",
    path: "windows/detections/crossview-byovd.kql",
    kind: "kql",
    summary:
      "Starter Sentinel / Defender KQL for the same hunts, plus a 15-minute DriverLoad → PPL-death join.",
    content: kql,
  },
  {
    id: "gap-csv",
    name: "loldrivers-gap.csv",
    path: "windows/detections/loldrivers-gap.csv",
    kind: "csv",
    summary:
      "Curated LOLDrivers sample (CSV twin of loldrivers-gap.json). Not a live VDBL scrape. Policy page renders the JSON feed.",
    content: gapCsv,
  },
  {
    id: "wdac",
    name: "wdac-checklist.md",
    path: "windows/detections/wdac-checklist.md",
    kind: "markdown",
    summary: "WDAC allow-known-good lab checklist. Live copy also on the Policy page.",
    content: wdacChecklist,
  },
];

export function kindBadgeVariant(
  kind: DetectionKind,
): "info" | "mute" | "medium" {
  switch (kind) {
    case "sysmon":
    case "sigma":
    case "kql":
      return "info";
    case "markdown":
    case "csv":
      return "mute";
    case "missing":
      return "medium";
    default: {
      const _exhaustive: never = kind;
      return _exhaustive;
    }
  }
}
