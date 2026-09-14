# WDAC allow-known-good (Windows 11)

Use the lab console **Policy** tab for the live checklist and the LOLDrivers hash feed.

## Order

1. Lab ring, not the fleet. Audit mode until 3076 is quiet.
2. Inventory loaded drivers. Managed installer does **not** authorize kernel drivers.
3. HVCI + Secure Boot + testsigning off.
4. Confirm inbox Windows Driver Policy is **enforced** (`{8F9CB695-5D48-48D6-A329-7202B44607E3}`).
5. Do **not** start from `DefaultWindows_*.xml` — it allows third-party kernel drivers.
6. `New-CIPolicy` a golden `System32\drivers` scan → audit → tune from 3076/3089.
7. Supplemental allows per role (GPU/VPN/backup), hash not Temp paths.
8. LOLDrivers gap as a **second base** (Allow All + Deny hashes). Convert the XML from the Hash feed tab.
9. Enforce, sign, `UpdatePolicySigners`. Keep a signed recovery policy.
10. Intune App Control for Business is the source of truth, not a copied CIP.
11. Monthly: refresh `aka.ms/VulnerableDriverBlockList` and this gap CSV.

## Convert the deny overlay

```
ConvertFrom-CIPolicy -XmlFilePath .\crossview-loldrivers-deny.xml `
  -BinaryFilePath .\{9F3C2A71-8B04-4E6D-A1C5-77D0E4B2C918}.cip
CiTool.exe --update-policy .\{9F3C2A71-8B04-4E6D-A1C5-77D0E4B2C918}.cip
```

Do not deploy that XML as your only policy — it contains Allow All by design so it can sit beside an allow-known-good base.
