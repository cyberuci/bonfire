$OutputFile = "tcp_connections_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Duration = 60
$EndTime = (Get-Date).AddSeconds($Duration)

$blockedPorts = @()
$excludedPorts = @()
$allExcludedPorts = $blockedPorts + $excludedPorts

Write-Host "Monitoring inbound TCP connections for $Duration seconds..."
Write-Host "Logging to: $OutputFile"

"Started at: $(Get-Date)" | Out-File -FilePath $OutputFile
"----------------------------------------" | Out-File -FilePath $OutputFile -Append

while ((Get-Date) -lt $EndTime) {
    $Connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    
    foreach ($conn in $Connections) {
        if ($allExcludedPorts -contains $conn.LocalPort) {
            continue
        }
        if ($conn.LocalPort -ge 49152 -and $conn.LocalPort -le 65535) {
            continue
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "$timestamp | Local Port: $($conn.LocalPort) | Remote: $($conn.RemoteAddress):$($conn.RemotePort)"
        $logEntry | Out-File -FilePath $OutputFile -Append
    }
    
    Start-Sleep -Seconds 1
}

"----------------------------------------" | Out-File -FilePath $OutputFile -Append
"Monitoring completed at: $(Get-Date)" | Out-File -FilePath $OutputFile -Append

Write-Host ""
Write-Host "Summary of unique local ports accessed:"
$ports = Get-Content $OutputFile | Where-Object { $_ -match "Local Port: (\d+)" } | 
    ForEach-Object { $matches[1] } | 
    Group-Object | 
    Sort-Object Count -Descending

$ports | ForEach-Object { Write-Host "$($_.Count) connections on port $($_.Name)" }

Write-Host ""
Write-Host "Full log saved to: $OutputFile"