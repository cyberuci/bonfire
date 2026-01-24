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