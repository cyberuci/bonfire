<#
.SYNOPSIS
    Reads and displays the Windows Firewall log file for quick traffic analysis.

.DESCRIPTION
    This script provides an efficient way to review firewall activity recorded in 'pfirewall.log'. 
    By default, it outputs the last 100 lines of the log directly to the console for a rapid 
    security snapshot. If the '-All' switch is used, the script opens the entire log file in 
    Notepad to allow for comprehensive manual searching and deeper forensic investigation.
#>

param(
    [switch]$All
)

$firewallLog = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

if (Test-Path $firewallLog) {
    if ($All) {
        Start-Process notepad $firewallLog
    } else {
        $allLines = Get-Content $firewallLog
        $totalLines = $allLines.Count
        
        if ($totalLines -gt 100) {
            $startIndex = $totalLines - 100
            $lines = $allLines[$startIndex..($totalLines - 1)]
        } else {
            $lines = $allLines
        }
        
        foreach ($line in $lines) {
            Write-Host $line
        }
    }
} else {
    Write-Host "Firewall log not found at $firewallLog" -ForegroundColor Red
}