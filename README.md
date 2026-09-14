# CROSSVIEW

Windows 11 x64 kernel-integrity scanner. Detection only — no exploit code, no hiding primitives.

Two halves:

| Path | What it is |
|---|---|
| `windows/` | WDM driver (`crossview.sys`), `cvscan.exe`, Win32 GUI. Compile and test-sign on a lab box. |
| `src/` | Browser lab console: technique matrix, FudModule 3.1 notes, Sigma/KQL pack, WDAC allow-known-good checklist, LOLDrivers vs Microsoft VDBL hash feed. |

The web console is documentation only and does not talk to the driver. Ring-0 walks only run after you build and load `crossview.sys` on Windows.

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

Vite + TanStack Router documentation UI. It does **not** talk to the Windows driver.

```bash
npm install
npm run dev
```

Serves the shell at `http://localhost:8080`. Production bundle: `npm run build` (typecheck + Vite) then `npm run preview`.

- `/` scanner fixture (docs only)
- `/matrix` technique matrix
- `/campaign` FudModule 3.1 notes
- `/detections` in-repo `windows/detections/` files (Sysmon, starter Sigma/KQL, curated LOLDrivers CSV, markdown)
- `/policy` WDAC checklist plus curated LOLDrivers hash-gap sample (empty state remains if the JSON has no rows)
- `/package` driver/CLI/GUI build notes
- `/cli` `cvscan.exe` flags

## Detections pack

`windows/detections/` — Sysmon fragment, starter Sigma, starter KQL, curated LOLDrivers-vs-VDBL JSON/CSV, WDAC checklist. The gap feed uses public loldrivers.io hashes; VDBL coverage flags are illustrative, not a weekly Microsoft scrape.

Deny overlay XML is not generated in this tree. When you build one from a real weekly feed, deploy it as a **second** App Control base policy (Allow All + Deny hashes), never as the only policy.

## License / use

Defensive lab tool. Do not use to develop, hide, or deploy rootkits.
