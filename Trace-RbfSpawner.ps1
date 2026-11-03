#Requires -RunAsAdministrator
<#
  Trace-RbfSpawner.ps1
  Finds what is repeatedly creating Config.Msi\*.rbf files.
  - Watches for *.rbf creation and logs the file deleted/moved right before it (the original file)
  - Logs every msiexec.exe launch with command line + full parent process chain
  - Streams MsiInstaller events live (self-repair 1001/1004, transactions 1040 w/ Client PID)
  - Temporarily enables verbose MSI logging, then greps those logs for the .rbf names
  - Dumps Defender detections (with the ProcessName that touched the file) at the end
  Usage:  .\Trace-RbfSpawner.ps1 -Minutes 120
#>
param(
    [int]$Minutes = 120,
    [string]$OutDir = 'C:\RbfTrace',
    [int]$HistoryDays = 3,
    [switch]$NoMsiLogging
)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$LogFile = Join-Path $OutDir ("trace_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$Start = Get-Date

function Write-Log([string]$Msg, [string]$Color = 'Gray') {
    $line = "[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}" -f (Get-Date), $Msg
    Add-Content -Path $LogFile -Value $line
    Write-Host $line -ForegroundColor $Color
}

# ---------- Product GUID -> name lookup ----------
$Products = @{}
'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |
    Where-Object { $_.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$' } |
    ForEach-Object { $Products[$_.PSChildName.ToUpper()] = "$($_.DisplayName) $($_.DisplayVersion)".Trim() }

function Resolve-Guids([string]$Text) {
    [regex]::Replace($Text, '\{[0-9A-Fa-f-]{36}\}', {
        param($m)
        $n = $Products[$m.Value.ToUpper()]
        if ($n) { "$($m.Value) [$n]" } else { $m.Value }
    })
}

function Get-ParentChain([int]$ProcId) {
    $seen = @{}
    while ($ProcId -and -not $seen.ContainsKey($ProcId)) {
        $seen[$ProcId] = $true
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcId" -ErrorAction SilentlyContinue
        if (-not $p) { "PID $ProcId (already exited)"; break }
        "PID $($p.ProcessId) $($p.Name) :: $($p.CommandLine)"
        $ProcId = $p.ParentProcessId
    }
}

function Write-MsiSnapshot {
    $procs = Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" -ErrorAction SilentlyContinue
    if (-not $procs) { Write-Log "    (no msiexec.exe running)"; return }
    foreach ($p in $procs) {
        Write-Log "    msiexec PID $($p.ProcessId) started $($p.CreationDate) :: $($p.CommandLine)" 'Yellow'
        Get-ParentChain $p.ParentProcessId | ForEach-Object { Write-Log "        <- $_" }
    }
}

function Format-MsiEvent($Evt) {
    $msg = ($Evt.Message -replace '\s+', ' ')
    if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + '...' }
    "MsiInstaller $($Evt.Id) @ $($Evt.TimeCreated): $(Resolve-Guids $msg)"
}

# ---------- 1. History: is this a self-repair loop? ----------
Write-Log "===== MsiInstaller history (last $HistoryDays days) =====" 'Cyan'
$hist = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; StartTime=(Get-Date).AddDays(-$HistoryDays) } -ErrorAction SilentlyContinue
if ($hist) {
    $hist | Group-Object Id | Sort-Object Count -Descending |
        ForEach-Object { Write-Log ("  Event {0}: {1} occurrences" -f $_.Name, $_.Count) }
    Write-Log "  -- Products appearing most often --"
    $hist | ForEach-Object { [regex]::Matches($_.Message, '\{[0-9A-Fa-f-]{36}\}') | Select-Object -First 1 | ForEach-Object { $_.Value.ToUpper() } } |
        Group-Object | Sort-Object Count -Descending | Select-Object -First 10 |
        ForEach-Object { Write-Log ("  {0,5}x  {1}" -f $_.Count, (Resolve-Guids $_.Name)) }
    Write-Log "  -- Latest self-repair / install events (1001,1004,1040,11707,11708,11724,1033,1034) --"
    $hist | Where-Object { $_.Id -in 1001,1004,1040,11707,11708,11724,1033,1034 } |
        Select-Object -First 15 | ForEach-Object { Write-Log ("  " + (Format-MsiEvent $_)) }
} else { Write-Log "  No MsiInstaller events found." }

# ---------- 2. Verbose MSI logging (restored at end) ----------
$PolKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
$OldLogging = $null
if (-not $NoMsiLogging) {
    if (-not (Test-Path $PolKey)) { New-Item $PolKey -Force | Out-Null }
    $OldLogging = (Get-ItemProperty $PolKey -Name Logging -ErrorAction SilentlyContinue).Logging
    Set-ItemProperty $PolKey -Name Logging -Value 'voicewarmupx'
    Write-Log "Verbose MSI logging enabled (logs -> $env:windir\Temp\MSI*.LOG)" 'Cyan'
}

# ---------- 3. Watchers ----------
$Root = "$env:SystemDrive\"
$rbfW = New-Object IO.FileSystemWatcher $Root, '*.rbf'
$delW = New-Object IO.FileSystemWatcher $Root
foreach ($w in $rbfW, $delW) {
    $w.IncludeSubdirectories = $true
    $w.InternalBufferSize    = 65536
    $w.NotifyFilter          = [IO.NotifyFilters]'FileName'
}
Register-ObjectEvent $rbfW Created -SourceIdentifier RbfCreated | Out-Null
Register-ObjectEvent $rbfW Renamed -SourceIdentifier RbfRenamed | Out-Null
Register-ObjectEvent $delW Deleted -SourceIdentifier AnyDeleted | Out-Null
Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='msiexec.exe'" -SourceIdentifier MsiStart | Out-Null
$rbfW.EnableRaisingEvents = $true
$delW.EnableRaisingEvents = $true

$RecentDeletes = New-Object System.Collections.Generic.List[object]
$RbfNames      = New-Object System.Collections.Generic.List[string]
$SeenRecords   = New-Object System.Collections.Generic.HashSet[long]
$LastMsiCheck  = Get-Date

function Add-Delete($e) {
    $path = $e.SourceEventArgs.FullPath
    if ($path -notlike "$OutDir*") { $RecentDeletes.Add([pscustomobject]@{ Time = $e.TimeGenerated; Path = $path }) }
}

Write-Log "===== Watching for $Minutes minutes. Ctrl+C to stop early. Log: $LogFile =====" 'Cyan'
$End = (Get-Date).AddMinutes($Minutes)
try {
    while ((Get-Date) -lt $End) {
        $e = Wait-Event -Timeout 2
        if ($e) {
            Remove-Event -EventIdentifier $e.EventIdentifier
            $src = $e.SourceIdentifier

            if ($src -eq 'AnyDeleted') { Add-Delete $e }

            elseif ($src -in 'RbfCreated', 'RbfRenamed') {
                $path = $e.SourceEventArgs.FullPath
                if ($path -match '\\Config\.Msi\\') {
                    Write-Log "######## RBF $($e.SourceEventArgs.ChangeType): $path" 'Red'
                    $RbfNames.Add([IO.Path]::GetFileName($path))
                    Start-Sleep -Milliseconds 300
                    # drain pending delete events so we can correlate the original file
                    Get-Event -SourceIdentifier AnyDeleted -ErrorAction SilentlyContinue | ForEach-Object {
                        Add-Delete $_; Remove-Event -EventIdentifier $_.EventIdentifier }
                    $win = $e.TimeGenerated.AddSeconds(-3)
                    $cands = $RecentDeletes | Where-Object { $_.Time -ge $win -and $_.Path -notmatch '\\Config\.Msi\\' }
                    if ($cands) { $cands | ForEach-Object { Write-Log "    Removed/moved just before (likely ORIGINAL file): $($_.Path)" 'Magenta' } }
                    else        { Write-Log "    No matching delete seen (original may be on another path/volume)" }
                    Write-MsiSnapshot
                }
            }

            elseif ($src -eq 'MsiStart') {
                $ne = $e.SourceEventArgs.NewEvent
                $p  = Get-CimInstance Win32_Process -Filter "ProcessId=$($ne.ProcessID)" -ErrorAction SilentlyContinue
                Write-Log "msiexec STARTED PID $($ne.ProcessID) :: $($p.CommandLine)" 'Yellow'
                Get-ParentChain $ne.ParentProcessID | ForEach-Object { Write-Log "    <- $_" }
            }
        }

        # trim delete buffer
        $cut = (Get-Date).AddSeconds(-15)
        $RecentDeletes.RemoveAll({ param($x) $x.Time -lt $cut }) | Out-Null

        # live MsiInstaller events
        $new = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='MsiInstaller'; StartTime=$LastMsiCheck } -ErrorAction SilentlyContinue
        foreach ($m in ($new | Sort-Object TimeCreated)) {
            if (-not $SeenRecords.Add($m.RecordId)) { continue }
            Write-Log (Format-MsiEvent $m) 'Green'
            if ($m.Message -match 'Client Process Id:\s*(\d+)') {
                Get-ParentChain ([int]$Matches[1]) | ForEach-Object { Write-Log "    client <- $_" }
            }
            if ($m.TimeCreated -gt $LastMsiCheck) { $LastMsiCheck = $m.TimeCreated }
        }
    }
}
finally {
    Write-Log "===== Stopping =====" 'Cyan'
    'RbfCreated','RbfRenamed','AnyDeleted','MsiStart' | ForEach-Object {
        Unregister-Event -SourceIdentifier $_ -ErrorAction SilentlyContinue }
    $rbfW.Dispose(); $delW.Dispose()

    if (-not $NoMsiLogging) {
        if ($null -ne $OldLogging) { Set-ItemProperty $PolKey -Name Logging -Value $OldLogging }
        else { Remove-ItemProperty $PolKey -Name Logging -ErrorAction SilentlyContinue }
        Write-Log "MSI logging policy restored."
    }

    # grep MSI verbose logs for the rbf names -> shows exact original file + product
    $msiLogs = Get-ChildItem "$env:windir\Temp\MSI*.LOG", "$env:TEMP\MSI*.LOG" -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -ge $Start }
    foreach ($n in ($RbfNames | Select-Object -Unique)) {
        Write-Log "--- MSI log hits for $n ---" 'Cyan'
        $msiLogs | Select-String -SimpleMatch $n -Context 4, 2 | Select-Object -First 5 | ForEach-Object {
            Write-Log "  $($_.Path):$($_.LineNumber)"
            $_.Context.PreContext + $_.Line + $_.Context.PostContext | ForEach-Object { Write-Log "    $_" }
        }
    }
    if ($msiLogs) {
        Write-Log "MSI logs written during trace (copied to $OutDir):"
        $msiLogs | ForEach-Object { Copy-Item $_.FullName $OutDir -ErrorAction SilentlyContinue; Write-Log "  $($_.Name)" }
    }

    # Defender detections during the trace
    if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
        $names = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $names[$_.ThreatID] = $_.ThreatName }
        Write-Log "--- Defender detections since $Start ---" 'Cyan'
        Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $Start.AddDays(-1) } |
            Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object {
                Write-Log "  $($_.InitialDetectionTime) $($names[$_.ThreatID]) Proc=$($_.ProcessName) User=$($_.DomainUser)"
                $_.Resources | ForEach-Object { Write-Log "      $_" }
            }
    }
    Write-Log "Done. Full log: $LogFile" 'Cyan'
}
