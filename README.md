# CROSSVIEW

Windows 11 x64 kernel-integrity scanner. Detection only — no exploit code, no hiding primitives.

Two halves:

| Path | What it is |
|---|---|
| `windows/` | WDM driver (`crossview.sys`), `cvscan.exe`, Win32 GUI. Compile and test-sign on a lab box. |
| `src/` | Browser lab console: technique matrix, FudModule 3.1 notes, Sigma/KQL pack, WDAC allow-known-good checklist, LOLDrivers vs Microsoft VDBL hash feed. |

The web console **simulates** scans. Ring 0 walks only run after you build and load the driver on Windows.

## Windows lab (real scanner)

Requires WDK + a test-signing certificate.

```bat
cd windows
build.bat
bcdedit /set testsigning on
sign.bat path\\to\\testcert.pfx
sc create CrossView type= kernel start= demand binPath= C:\\lab\\crossview.sys
cvscan.exe --fudmodule
```

See [windows/README.md](windows/README.md).

## Web lab

```bash
npm install
npm run dev
```

- `/` scanner fixture
- `/matrix` technique matrix
- `/campaign` FudModule 3.1
- `/detections` Sigma + KQL
- `/policy` WDAC checklist + LOLDrivers hash gap
- `/package` driver/CLI/GUI download notes

## Detections pack

`windows/detections/` — Sysmon fragment, Sigma, KQL, LOLDrivers-vs-VDBL CSV, WDAC checklist.

Deny overlay XML is generated from the Policy → Hash feed tab. Deploy it as a **second** App Control base policy (Allow All + Deny hashes), never as the only policy.

## License / use

Defensive lab tool. Do not use to develop, hide, or deploy rootkits.
