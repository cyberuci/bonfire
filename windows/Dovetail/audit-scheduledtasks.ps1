<#
.SYNOPSIS
    Audits Windows Scheduled Tasks for suspicious configurations and potential persistence mechanisms.

.DESCRIPTION
    This script reviews all scheduled tasks on a local system to identify indicators 
    of malicious activity or unauthorized persistence. It analyzes task actions and 
    flags configurations that:
    - Execute from user-writable or temporary directories (e.g., AppData, Temp, C:\Users).
    - Utilize encoded PowerShell commands.
    - Run with elevated privileges (SYSTEM/NT AUTHORITY) but execute binaries from user-controlled paths.
    - Have been recently created or modified (defaults to within the last 7 days).
    
    To minimize noise, standard and unmodified Microsoft scheduled tasks are hidden by 
    default. This behavior can be overridden with the '-ShowAll' switch. All findings 
    can be exported to a CSV file for reporting or further analysis using the '-Export' 
    parameter.
#>

param(
    [int]$DaysBack    = 7,
    [string]$Export   = "",
    [switch]$ShowAll
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "            Audit-ScheduledTasks" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""


$cutoff   = (Get-Date).AddDays(-$DaysBack)
$findings = [System.Collections.Generic.List[PSObject]]::new()

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $tasks) {
    $flags   = [System.Collections.Generic.List[string]]::new()
    $action  = $task.Actions | Select-Object -First 1
    $execute = if ($action) { $action.Execute }   else { "" }
    $args    = if ($action) { $action.Arguments } else { "" }
    $runAs   = $task.Principal.UserId
    $fullCmd = "$execute $args"

    # Suspicious execution path
    if ($fullCmd -match 'C:\\Users|%TEMP%|%APPDATA%|C:\\Temp|\\AppData\\|C:\\Windows\\Temp') {
        $flags.Add("suspicious-path")
    }

    # Encoded PowerShell command
    if ($fullCmd -match '-[Ee]nc(odedCommand)?[\s=]|[A-Za-z0-9+/]{80,}={0,2}') {
        $flags.Add("encoded-command")
    }

    # SYSTEM task with user-controlled path
    if ($runAs -match 'SYSTEM|NT AUTHORITY' -and $fullCmd -match 'C:\\Users|%TEMP%|%APPDATA%') {
        $flags.Add("system+user-path")
    }

    # Recently modified
    $taskFile = "C:\Windows\System32\Tasks$($task.TaskPath)$($task.TaskName)"
    if (Test-Path $taskFile -ErrorAction SilentlyContinue) {
        $fi = Get-Item $taskFile -ErrorAction SilentlyContinue
        if ($fi -and $fi.LastWriteTime -gt $cutoff) {
            $flags.Add("recently-modified:$($fi.LastWriteTime.ToString('yyyy-MM-dd'))")
        }
    }

    $isMicrosoft = $task.TaskPath -match '^\\Microsoft\\'
    if ($isMicrosoft -and $flags.Count -eq 0 -and -not $ShowAll) { continue }

    $findings.Add([PSCustomObject]@{
        Path        = $task.TaskPath
        Name        = $task.TaskName
        State       = $task.State.ToString()
        RunAs       = $runAs
        Execute     = $execute
        Arguments   = $args
        IsMicrosoft = $isMicrosoft
        Flags       = ($flags -join " | ")
    })
}

$flagged    = @($findings | Where-Object { $_.Flags })
$unflagged  = @($findings | Where-Object { -not $_.Flags })

Write-Host ""
Write-Host "[*] Tasks reviewed: $($findings.Count)  |  Flagged: $($flagged.Count)" -ForegroundColor Cyan
Write-Host ""

if ($flagged.Count -gt 0) {
    Write-Host "=== FLAGGED TASKS ===" -ForegroundColor Red
    $flagged | Format-Table Path, Name, RunAs, Flags, Execute -AutoSize | Out-String | Write-Host -ForegroundColor Red
}

if ($unflagged.Count -gt 0) {
    $label = if ($ShowAll) { "=== ALL OTHER TASKS ===" } else { "=== NON-MICROSOFT TASKS (UNFLAGGED) ===" }
    Write-Host $label -ForegroundColor Yellow
    $unflagged | Format-Table Path, Name, State, RunAs, Execute -AutoSize | Out-String | Write-Host
}

if ($Export) {
    $findings | Export-Csv -Path $Export -NoTypeInformation
    Write-Host "[+] Exported to $Export" -ForegroundColor Cyan
}
