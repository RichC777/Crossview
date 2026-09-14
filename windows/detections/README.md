# CROSSVIEW BYOVD SIEM pack

Defensive detections only. No IOCTL maps, no exploit steps, no "drivers that still load under HVCI."

Export the live YAML/KQL from the lab console **Rules** page, or drop these files into Sigma / Sentinel / Defender.

## What is covered

| Family | Signal | Why |
|---|---|---|
| Code Integrity | 3077, 3076, 3001/3004/3033, 3021/3112, 3111 | VDBL/WDAC/HVCI said no — or would have |
| SCM | 7045, 4697, sc.exe / pnputil | Kernel driver service registered, especially from Temp/Users |
| Sysmon | Event 6 | Bytes actually entered the kernel. **Do not exclude Signed=true** |
| PPL / EDR | Sysmon 5, 4689, 7034/7036/7040 | Security process/service died. Kernel bypasses PPL |
| Clock | 4616, w32time stop, Set-Date | Retrosign: backdate, load a pre-cutoff signed driver |
| Correlation | 15–30 min joins | Driver load → EDR death; clock tamper → driver load; mapper unload |

Filename matches against well-known LOLDrivers names are a **floor**. Production should hash-match [loldrivers.io](https://www.loldrivers.io/).

## Enablement (do this first)

1. **Code Integrity Operational** — on by default. Confirm 3076/3077 in lab.
2. **Sysmon DriverLoad** — use `sysmon-crossview.xml`. The SwiftOnSecurity-style "exclude signed" filter is how BYOVD hides.
3. **Audit Security System Extension** — Security 4697 (who installed the service).
4. **Audit Security State Change** — Security 4616 (clock). Retrosign is silent without this.
5. **Sysmon ProcessTerminate (5)** and **ProcessAccess (10)** to `lsass.exe`.
6. Forward CodeIntegrity, System, Security to Sentinel. MDE `DeviceEvents` ActionType `DriverLoad` is the Defender twin of Sysmon 6.

## Tuning

- 7045 on `System32\drivers` and `DriverStore` is usually OEM/WU. Alert when ImagePath is user-writable.
- 4616 from `LOCAL SERVICE` is often NTP. Alert on day/year deltas, not on 2-second slews.
- PPL death during Patch Tuesday: look for msiexec / trusted installer in the same window. No installer + a driver load = incident.
- HVCI 3111 catches mappers. It does **not** catch a loaded vuln driver calling `ZwTerminateProcess`. Keep the PPL-death rules.

## Files

- `sysmon-crossview.xml` — merge into your Sysmon config
- Sigma / KQL — download from the Rules page (`crossview-byovd-sigma.yml`, `crossview-byovd.kql`)
- `loldrivers-gap.csv` — LOLDrivers samples not hash-blocked by this week's Microsoft VDBL (also on the Policy page)
- Deny XML — generate from the Policy → Hash feed tab (Allow All + Deny; deploy as a **second** base policy)
