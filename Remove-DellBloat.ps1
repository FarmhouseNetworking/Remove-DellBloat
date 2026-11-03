#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes Dell consumer/support bloatware (SupportAssist, TechHub/Core Services, Digital Delivery,
    Optimizer, Peripheral Manager, etc.) silently. Safe to push via RMM (runs fine as SYSTEM).

.DESCRIPTION
    Order of operations:
      1. Stop + disable matching services, kill their processes (breaks update/repair loops)
      2. Remove matching scheduled tasks
      3. Uninstall matching Win32 apps (bundles first, then any leftover hidden MSIs), 3 passes
      4. Remove matching AppX / provisioned AppX packages
      5. Optionally delete leftover folders
    KEPT by default: Dell Command suite (Update/Configure/Monitor), drivers, firmware/BIOS,
    Dell Display Manager, audio (Waves/Realtek), and Dell Encryption / Data Protection /
    Trusted Device / Security Management (removing those can break encrypted machines).

.PARAMETER RemoveCommandUpdate   Also remove Dell Command | Update.
.PARAMETER RemoveLeftovers       Delete leftover program/data folders after uninstall.
.PARAMETER ListOnly              Only list what would be targeted, change nothing.
.EXAMPLE
    .\Remove-DellBloat.ps1 -ListOnly
    .\Remove-DellBloat.ps1 -RemoveLeftovers
.NOTES
    Exit codes: 0 = clean, 3010 = clean but reboot required, 1 = something left behind (see log)
#>
[CmdletBinding()]
param(
    [switch]$RemoveCommandUpdate,
    [switch]$RemoveLeftovers,
    [switch]$ListOnly,
    [int]$TimeoutSeconds = 900,
    [string]$LogDir = "$env:ProgramData\DellCleanup"
)

# ---------------- What to remove / keep ----------------
$Targets = @(
    'SupportAssist'               # SupportAssist, Agent, Remediation, OS Recovery Plugin
    'Dell Core Services'
    'Dell TechHub'
    'Dell Digital Delivery'
    'Dell Optimizer'
    'DellOptimizer'               # "DellOptimizerUI" has no space
    'Dell Precision Optimizer'
    'Dell Power Manager'
    'Dell Peripheral Manager'
    'Dell Customer Connect'
    'Dell Mobile Connect'
    'Dell Pair'
    'Dell Update'                 # consumer "Dell Update" (not Command | Update)
    'Dell Foundation Services'
    'Dell Help & Support'
    'Dell Product Registration'
    'My Dell'
    'Dell Partner Promo'
    'Dell Cinema'
)
$Keep = @(
    'Dell Command', 'Driver', 'Firmware', 'BIOS', 'Dell Display Manager', 'Waves', 'Realtek',
    'Audio', 'Touchpad', 'Encryption', 'Data Protection', 'Trusted Device', 'Security Management',
    'Dell Threat'
)
$AppxTargets = @(
    'DellSupportAssistforPCs', 'DellDigitalDelivery', 'DellCustomerConnect', 'DellPowerManager',
    'DellOptimizer', 'PartnerPromo', 'DellUpdate', 'MyDell', 'DellMobileConnect', 'DellPair',
    'DellProductRegistration', 'DellHelpSupport', 'DellCinemaGuide'
)
if ($RemoveCommandUpdate) {
    $Targets     += 'Dell Command \| Update'
    $Keep         = $Keep | Where-Object { $_ -ne 'Dell Command' }
    $Keep        += 'Dell Command \| (Configure|Monitor|Power)'
    $AppxTargets += 'DellCommandUpdate'
}
$LeftoverFolders = @(
    "$env:ProgramFiles\Dell\SupportAssistAgent"
    "$env:ProgramFiles\Dell\SARemediation"
    "$env:ProgramFiles\Dell\TechHub"
    "$env:ProgramFiles\Dell\DellOptimizer"
    "$env:ProgramFiles\Dell\Dell Peripheral Manager"
    "$env:ProgramFiles\Dell\DellPowerManager"
    "${env:ProgramFiles(x86)}\Dell Digital Delivery Services"
    "$env:ProgramData\Dell\SARemediation"
    "$env:ProgramData\Dell\TechHub"
    "$env:ProgramData\SupportAssist"
    "$env:ProgramData\Dell\DellOptimizer"
)

$TargetRx  = ($Targets | ForEach-Object { if ($_ -match '\\') { $_ } else { [regex]::Escape($_) } }) -join '|'
$KeepRx    = ($Keep    | ForEach-Object { if ($_ -match '\\') { $_ } else { [regex]::Escape($_) } }) -join '|'
$AppxRx    = '^DellInc\.(' + ($AppxTargets -join '|') + ')'
$FolderRx  = ($LeftoverFolders | Where-Object { $_ -notmatch '^\\' } | ForEach-Object { '^' + [regex]::Escape($_) }) -join '|'

# ---------------- Logging ----------------
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Transcript = Join-Path $LogDir ("DellCleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $Transcript -Force | Out-Null
function Log([string]$m) { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }

function Test-Target([string]$Name) {
    $Name -and $Name -match $TargetRx -and $Name -notmatch $KeepRx
}

function Get-DellApps {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { (Test-Target $_.DisplayName) -and ($_.Publisher -match 'Dell' -or $_.DisplayName -match '^Dell|SupportAssist') } |
        Sort-Object @{ e = { [int]($_.SystemComponent -eq 1) } }, DisplayName   # visible bundles before hidden MSIs
}

function Invoke-Uninstall($App) {
    $name = $App.DisplayName
    $guid = if ($App.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $App.PSChildName }
    $cmd  = if ($App.QuietUninstallString) { $App.QuietUninstallString } else { $App.UninstallString }

    if ($cmd -match 'msiexec' -or ($guid -and $App.WindowsInstaller -eq 1)) {
        if (-not $guid -and $cmd -match '\{[0-9A-Fa-f-]{36}\}') { $guid = $Matches[0] }
        if (-not $guid) { Log "  !! $name : MSI but no product code found"; return 1 }
        $file    = "$env:SystemRoot\System32\msiexec.exe"
        $argList = "/x $guid /qn /norestart REBOOT=ReallySuppress /L*v `"$LogDir\$guid.log`""
    }
    elseif ($cmd) {
        if     ($cmd -match '^\s*"([^"]+)"\s*(.*)$')   { $file = $Matches[1]; $argList = $Matches[2] }
        elseif ($cmd -match '^\s*(.+?\.exe)\s*(.*)$') { $file = $Matches[1]; $argList = $Matches[2] }
        else   { $file = $cmd; $argList = '' }

        if (-not $App.QuietUninstallString) {
            if ($file -match 'Package Cache' -or $argList -match '/uninstall') {        # WiX Burn bundle
                if ($argList -notmatch '/uninstall') { $argList += ' /uninstall' }
                if ($argList -notmatch '/quiet')     { $argList += ' /quiet /norestart' }
            }
            elseif ($cmd -match 'InstallShield|-remove') {                             # InstallShield (e.g. Dell Optimizer)
                if ($argList -notmatch 'silent') { $argList += ' -silent' }
            }
            elseif ($argList -notmatch '(^|\s)[/-](S|silent|quiet|qn)\b') {            # NSIS / generic
                $argList += ' /S'
            }
        }
        if (-not (Test-Path $file)) { Log "  !! $name : uninstaller missing ($file)"; return 1 }
    }
    else { Log "  !! $name : no uninstall string"; return 1 }

    Log "  -> $name : `"$file`" $argList"
    try {
        $p = Start-Process -FilePath $file -ArgumentList $argList -PassThru -WindowStyle Hidden -ErrorAction Stop
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            Log "  !! $name : timed out after $TimeoutSeconds s, killing"
            $p | Stop-Process -Force -ErrorAction SilentlyContinue
            return 1
        }
        Log "     exit code $($p.ExitCode)"
        return $p.ExitCode
    } catch { Log "  !! $name : $($_.Exception.Message)"; return 1 }
}

# ---------------- Inventory ----------------
Log "===== Dell cleanup on $env:COMPUTERNAME ====="
$apps = @(Get-DellApps)
Log "Win32 apps targeted: $($apps.Count)"
$apps | ForEach-Object { Log ("  {0} {1}  [{2}]" -f $_.DisplayName, $_.DisplayVersion, $_.PSChildName) }

$appx = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $AppxRx })
$prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $AppxRx })
Log "AppX targeted: $($appx.Count) installed, $($prov.Count) provisioned"
$appx | ForEach-Object { Log "  $($_.PackageFullName)" }

$services = @(Get-CimInstance Win32_Service | Where-Object {
    ((Test-Target $_.DisplayName) -or ($FolderRx -and $_.PathName -and ($_.PathName.Trim('"') -match $FolderRx))) -and $_.DisplayName -notmatch $KeepRx })
Log "Services targeted: $($services.Count)"
$services | ForEach-Object { Log "  $($_.Name) ($($_.DisplayName)) $($_.State)" }

$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    "$($_.TaskPath)$($_.TaskName)" -match 'SupportAssist|TechHub|Digital Delivery|DellOptimizer|Dell Optimizer|Dell Update|Dell Core Services|Peripheral Manager' -and
    "$($_.TaskPath)$($_.TaskName)" -notmatch $KeepRx })
Log "Scheduled tasks targeted: $($tasks.Count)"
$tasks | ForEach-Object { Log "  $($_.TaskPath)$($_.TaskName)" }

if ($ListOnly) { Log "ListOnly - no changes made."; Stop-Transcript | Out-Null; exit 0 }

# ---------------- 1. Services + processes ----------------
foreach ($s in $services) {
    Log "Stopping/disabling service $($s.Name)"
    Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
    Set-Service  -Name $s.Name -StartupType Disabled -ErrorAction SilentlyContinue
}
if ($FolderRx) {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -match $FolderRx } | ForEach-Object {
        Log "Killing process $($_.Name) ($($_.Id))"
        $_ | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

# ---------------- 2. Scheduled tasks ----------------
foreach ($t in $tasks) {
    Log "Removing task $($t.TaskPath)$($t.TaskName)"
    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
}

# ---------------- 3. Win32 uninstalls (multi-pass) ----------------
$reboot = $false
$tried  = @{}
for ($pass = 1; $pass -le 3; $pass++) {
    $todo = @(Get-DellApps | Where-Object { -not $tried.ContainsKey($_.PSChildName) })
    if (-not $todo) { break }
    Log "--- Uninstall pass $pass ($($todo.Count) items) ---"
    foreach ($a in $todo) {
        # skip if an earlier uninstall in this pass already removed it
        $still = Get-DellApps | Where-Object { $_.PSChildName -eq $a.PSChildName }
        if (-not $still) { continue }
        $tried[$a.PSChildName] = $true
        $rc = Invoke-Uninstall $a
        if ($rc -in 3010, 1641) { $reboot = $true }
    }
}

# ---------------- 4. AppX ----------------
foreach ($p in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $AppxRx })) {
    Log "Removing AppX $($p.PackageFullName)"
    try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop }
    catch { Log "  !! $($_.Exception.Message)" }
}
foreach ($p in @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $AppxRx })) {
    Log "Removing provisioned AppX $($p.PackageName)"
    try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null }
    catch { Log "  !! $($_.Exception.Message)" }
}

# ---------------- 5. Leftovers ----------------
if ($RemoveLeftovers) {
    foreach ($f in $LeftoverFolders) {
        if (Test-Path $f) {
            Log "Deleting leftover folder $f"
            Remove-Item $f -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $f) { Log "  !! could not fully delete (files in use? reboot and rerun)" }
        }
    }
}

# ---------------- Result ----------------
$left     = @(Get-DellApps)
$leftAppx = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $AppxRx })
Log "===== Remaining: $($left.Count) Win32, $($leftAppx.Count) AppX ====="
$left     | ForEach-Object { Log "  STILL INSTALLED: $($_.DisplayName) [$($_.PSChildName)]  $($_.UninstallString)" }
$leftAppx | ForEach-Object { Log "  STILL INSTALLED: $($_.PackageFullName)" }
Log "Log: $Transcript"
Stop-Transcript | Out-Null

if ($left.Count -or $leftAppx.Count) { exit 1 }
elseif ($reboot)                     { exit 3010 }
else                                 { exit 0 }
