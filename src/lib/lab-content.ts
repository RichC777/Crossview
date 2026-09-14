export const SCANNER_MODULES = [
  {
    module: "Process cross-view",
    techniques: "T2.b T2.j",
    note: "ActiveProcessLinks walk vs CID (user-mode).",
  },
  {
    module: "Token / PPL",
    techniques: "T2.d T15.d T15.e",
    note: "Token and PPL field cross-checks.",
  },
  {
    module: "Drivers / BYOVD",
    techniques: "T2.a T16.a T14.d",
    note: "LOLDrivers names in PsLoadedModules.",
  },
  {
    module: "Callbacks",
    techniques: "T11.a",
    note: "Export-LEA walk of Psp*NotifyRoutine + WdFilter cross-view.",
  },
  {
    module: "ETW",
    techniques: "T15.b T12.c T12.d",
    note: "94-GUID FudModule kill-list probe from the CLI.",
  },
  {
    module: "Minifilters",
    techniques: "T12.e",
    note: "FltEnumerateFilterInformation + WdFilter/328010 cross-view.",
  },
  {
    module: "WFP / network",
    techniques: "T12.b",
    note: "Fwpm provider/callout/filter enum from the CLI (BFE).",
  },
  {
    module: "Inline / SSDT / IDT / LSTAR",
    techniques: "T1.* T3.* T5.a",
    note: "Hook and table integrity modules.",
  },
  {
    module: "Dispatch",
    techniques: "T4.d T4.e T4.f",
    note: "AFD / NSI / Null dispatch hooks.",
  },
  {
    module: "Crash dumps",
    techniques: "T12.i",
    note: "Export-LEA walk of KeBugCheck* callback lists + LDR orphan cross-view.",
  },
  {
    module: "Integrity",
    techniques: "T14.d T15.c",
    note: "afd.sys vs KB5121003, SAC.",
  },
] as const;

export const CLI_FLAGS = [
  { flag: "--install", detail: "Create and start the CrossView service." },
  { flag: "--uninstall", detail: "Stop and delete the service." },
  { flag: "--quick", detail: "Process, token, callbacks, ETW, BYOVD, integrity." },
  { flag: "--full", detail: "Every module including SSDT, IDT, hooks, stacks." },
  { flag: "--fudmodule", detail: "Hunt FudModule 3.1 TTPs (default if no profile)." },
  { flag: "--json", detail: "Machine-readable findings on stdout." },
  { flag: "--quiet", detail: "Findings only, no banner." },
  { flag: "--no-driver", detail: "Skip kernel IOCTL (user-mode views only)." },
  { flag: "--out FILE", detail: "Write JSON report." },
] as const;

export const WDAC_STEPS = [
  "Lab ring, not the fleet. Audit mode until 3076 is quiet.",
  "Inventory loaded drivers. Managed installer does not authorize kernel drivers.",
  "HVCI + Secure Boot + testsigning off.",
  "Confirm inbox Windows Driver Policy is enforced ({8F9CB695-5D48-48D6-A329-7202B44607E3}).",
  "Do not start from DefaultWindows_*.xml — it allows third-party kernel drivers.",
  "New-CIPolicy a golden System32\\drivers scan → audit → tune from 3076/3089.",
  "Supplemental allows per role (GPU/VPN/backup), hash not Temp paths.",
  "LOLDrivers gap as a second base (Allow All + Deny hashes).",
  "Enforce, sign, UpdatePolicySigners. Keep a signed recovery policy.",
  "Intune App Control for Business is the source of truth, not a copied CIP.",
  "Monthly: refresh aka.ms/VulnerableDriverBlockList and the gap CSV.",
] as const;
