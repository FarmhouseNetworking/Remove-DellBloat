# Remove-DellBloat

PowerShell tools for removing Dell consumer/support software from managed Windows machines, plus a tracer for finding what keeps creating `C:\Config.Msi\*.rbf` rollback files.

## Background

SentinelOne kept flagging `C:\Config.Msi\<random>.rbf` as ransomware ("Shadow Copy Deletion detected" / "Application was hijacked by a suspicious DLL"). The file kept coming back after each mitigation.

- `.rbf` files are Windows Installer rollback backups. When MSI replaces a file, it first moves the old copy into `Config.Msi` under a random name.
- In this case the process behind it was **Dell TechHub** (`C:\Program Files\Dell\TechHub\Dell.TechHub.exe`, the `DellTechHub` service, installed as part of Dell Core Services), running as SYSTEM under `services.exe`.
- The Application event log showed MsiInstaller event **1035** ("Windows Installer reconfigured the product") for every Dell product within a few seconds, repeating every few days. Each repair wrote new `.rbf` files and set off the EDR again.

Removing the Dell support software stops the loop.

## Remove-DellBloat.ps1

Silently removes Dell support software. It's safe to run as SYSTEM from an RMM tool.

**Removes:** SupportAssist (and Remediation, OS Recovery Plugin), Dell Core Services / TechHub, Dell Digital Delivery, Dell Optimizer (Core, UI), Power Manager, Peripheral Manager, Customer Connect, Mobile Connect, Dell Pair, consumer Dell Update, Foundation Services, Help & Support, Product Registration, My Dell, and their AppX / provisioned AppX packages, services, and scheduled tasks.

**Keeps by default:** Dell Command suite (Update / Configure / Monitor), drivers, firmware/BIOS, Dell Display Manager, audio (Waves/Realtek), and Dell Encryption / Data Protection / Trusted Device / Security Management. Removing those can break encrypted machines.

### What it does, in order

1. Stops and disables the matching services and kills their processes, which breaks any repair loop right away.
2. Removes the matching scheduled tasks.
3. Uninstalls the Win32 apps: visible bundles first, then any leftover hidden MSIs, in up to 3 passes.
   - MSI packages: `msiexec /x {GUID} /qn /norestart`
   - WiX Burn bundles: `/uninstall /quiet /norestart`
   - InstallShield (e.g. Dell Optimizer): `-silent`
4. Removes the AppX and provisioned AppX packages.
5. Optionally deletes leftover folders (`-RemoveLeftovers`).

### Usage

Preview what it would remove (changes nothing):

```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-DellBloat.ps1 -ListOnly
```

Remove everything listed, including leftover folders:

```powershell
powershell -ExecutionPolicy Bypass -File .\Remove-DellBloat.ps1 -RemoveLeftovers
```

| Parameter | Purpose |
|---|---|
| `-ListOnly` | Show what would be removed and stop |
| `-RemoveLeftovers` | Delete leftover program/data folders afterwards |
| `-RemoveCommandUpdate` | Also remove Dell Command \| Update |
| `-TimeoutSeconds` | Per-uninstaller timeout (default 900) |
| `-LogDir` | Log location (default `C:\ProgramData\DellCleanup`) |

**Exit codes:** `0` = clean, `3010` = clean but a reboot is required, `1` = something was left behind (the log lists it under `STILL INSTALLED`).

After removal, open Dell Command | Update and run a check. If it complains about missing components, reinstall just Command | Update from Dell.

## Trace-RbfSpawner.ps1

Finds what is repeatedly creating `Config.Msi\*.rbf` files. Run it elevated and leave it running until the file reappears.

```powershell
.\Trace-RbfSpawner.ps1 -Minutes 120
```

What it records:

- MsiInstaller history for the last few days (self-repair events 1001/1004, transactions, the most frequent products).
- Every `msiexec.exe` launch, with its command line and full parent process chain.
- Each `.rbf` creation, plus the file removed or moved just before it (the original file the AV is really reacting to).
- Live MsiInstaller events, including the client process behind each transaction.
- Verbose MSI logging while it runs. The script turns this back off at the end, then searches those logs for the `.rbf` names.
- Microsoft Defender detections during the trace.

Output goes to `C:\RbfTrace`. If the script is killed instead of stopped with Ctrl+C, turn verbose MSI logging back off with:

```powershell
Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name Logging
```
