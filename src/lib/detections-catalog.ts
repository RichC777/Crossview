import detectionsReadme from "../../windows/detections/README.md?raw";
import wdacChecklist from "../../windows/detections/wdac-checklist.md?raw";
import sysmonXml from "../../windows/detections/sysmon-crossview.xml?raw";

export type DetectionKind = "sysmon" | "markdown" | "missing";

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
    id: "wdac",
    name: "wdac-checklist.md",
    path: "windows/detections/wdac-checklist.md",
    kind: "markdown",
    summary: "WDAC allow-known-good lab checklist. Live copy also on the Policy page.",
    content: wdacChecklist,
  },
  {
    id: "sigma",
    name: "crossview-byovd-sigma.yml",
    path: "windows/detections/",
    kind: "missing",
    summary:
      "Sigma YAML is not in this tree. The detections README still points at a Rules-page export that has not been checked in.",
  },
  {
    id: "kql",
    name: "crossview-byovd.kql",
    path: "windows/detections/",
    kind: "missing",
    summary: "KQL is not in this tree. Same gap as the Sigma pack.",
  },
  {
    id: "gap-csv",
    name: "loldrivers-gap.csv",
    path: "windows/detections/",
    kind: "missing",
    summary: "LOLDrivers-vs-VDBL CSV is not in this tree. Policy shows an empty hash-gap state.",
  },
];
