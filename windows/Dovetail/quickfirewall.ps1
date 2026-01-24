param (
    [string[]]$in,
    [string[]]$out,
    [switch]$udp
)

$excludedPorts = 

if (-not $in -and -not $out) {
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  -in <port(s)>"
    Write-Host "  -out <port(s)>" 
    Write-Host ""

    Write-Host "Ports:" -ForegroundColor Yellow
    $netstatOutput = netstat -an | Select-String "TCP.*LISTENING" | Where-Object { $_ -notmatch '127\.0\.0\.1' -and $_ -notmatch '\[::1\]' }
    $allPorts = $netstatOutput | ForEach-Object {
        if ($_ -match ':(\d+)\s+.*LISTENING') {
            [int]$matches[1]
        }
    } | Select-Object -Unique | Sort-Object
    $excludedPortsList = $excludedPorts.Split(',') | ForEach-Object { [int]$_.Trim() }
    $filteredPorts = $allPorts | Where-Object {
        $excludedPortsList -notcontains $_ -and ($_ -lt 49152 -or $_ -gt 65535)
    }
    foreach ($port in $filteredPorts) {
        Write-Host "  $($port)" 
    }
    Write-Host "" 

    return
}

$protocol = if ($udp) { 'udp' } else { 'tcp' }

function Expand-PortList {
    param([string[]]$portList)
    
    $expandedPorts = @()
    foreach ($item in $portList) {
        if ($item -match '^(\d+)-(\d+)$') {
            $start = [int]$matches[1]
            $end = [int]$matches[2]
            $expandedPorts += "$start-$end"
        } else {
            $expandedPorts += $item
        }
    }
    return $expandedPorts
}

if ($in) {
    $expandedIn = Expand-PortList -portList $in
    foreach ($port in $expandedIn) {
        Write-Host "netsh a f a r n=$($port)_$($protocol.ToUpper())_In dir=in a=allow prot=$protocol localport=$($port)" 
        netsh a f a r n=$($port)_$($protocol.ToUpper())_In dir=in a=allow prot=$protocol localport=$($port)
    }
}

if ($out) {
    $expandedOut = Expand-PortList -portList $out
    foreach ($port in $expandedOut) {
        Write-Host "netsh a f a r n=$($port)_$($protocol.ToUpper())_Out dir=out a=allow prot=$protocol remoteport=$($port)" 
        netsh a f a r n=$($port)_$($protocol.ToUpper())_Out dir=out a=allow prot=$protocol remoteport=$($port)
    }
}

