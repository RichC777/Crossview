# CROSSVIEW — Windows 11 x64 kernel integrity scanner

Detection-only lab tool. Compares multiple views of kernel objects to find rootkit hiding (DKOM, callback teardown, ETW blinding, BYOVD residue, dispatch hooks). Tuned for **Lazarus FudModule 3.1** (CVE-2026-68820 / Operation Dream Job, August 2026).

**This tree contains no exploit code, no hiding primitives, and no EDR killer.**

## Layout

```
shared/CrossViewShared.h   IOCTL protocol (driver + CLI + GUI)
driver/                    WDM software driver → crossview.sys
cli/cvscan.c               Command-line scanner
gui/main.c                 Dark Win32 GUI
inf/CrossView.inf          Optional PnP install
detections/                Sigma + KQL + Sysmon fragment (BYOVD SIEM pack)
build.bat / sign.bat
```

## Lab build

1. Visual Studio 2022 (C++) + WDK 10 matching the Windows 11 SDK.
2. `build.bat` from an x64 Native Tools prompt.
3. Enable test signing, reboot, sign with your test cert:

```
bcdedit /set testsigning on
shutdown /r /t 0
sign.bat YourTestCert.pfx
```

4. Load and scan (admin):

```
sc create CrossView type= kernel start= demand binPath= C:\lab\crossview.sys
sc start CrossView
cvscan.exe --fudmodule
cvscan.exe --full --json --out report.json
CrossView.exe
```

## What it looks for

| Module | Techniques |
|---|---|
| Process cross-view | T2.b T2.j — ActiveProcessLinks walk vs CID (usermode) |
| Token / PPL | T2.d T15.d T15.e |
| Drivers / BYOVD | T2.a T16.a T14.d — LOLDrivers names in PsLoadedModules |
| Callbacks | T11.a — export-LEA walk of Psp*NotifyRoutine + WdFilter cross-view |
| ETW | T15.b T12.c T12.d — 94-GUID kill-list from the CLI |
| Minifilters | T12.e — FltEnumerateFilterInformation + WdFilter/328010 cross-view |
| WFP / network | T12.b — Fwpm provider/callout/filter enum from the CLI (BFE) |
| Inline / SSDT / IDT / LSTAR | T1.* T3.* T5.a |
| Dispatch | T4.d T4.e T4.f — AFD / NSI / Null |
| Crash dumps | T12.i |
| Integrity | T14.d T15.c — afd.sys vs KB5121003, SAC |

FudModule 3.1 is **data-only**. A clean SSDT/hook scan plus dead ETW and empty EDR callback slots **is the hit**, not a clean bill of health.

## SIEM pack (`detections/`)

Sigma + KQL for the BYOVD *approach* to the kernel: Code Integrity 3076/3077, SCM 7045 from user-writable paths, Sysmon 6 (signed drivers included), PPL/EDR death, 4616/w32time clock tamper, and 15-minute correlations. Merge `sysmon-crossview.xml` into Sysmon — do not exclude `Signed=true` on DriverLoad.

Download YAML/KQL from the lab console Rules page.

## Safety

- Unknown EPROCESS layouts: the driver **refuses** the process walk instead of guessing.
- Every kernel list walk is SEH-wrapped.
- IOCTLs are METHOD_BUFFERED. The driver never writes kernel memory.
- Test-signed only. Do not load on a production endpoint.

## License / use

Lab research on machines you own. Not an EDR replacement.
