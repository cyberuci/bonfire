<#
.SYNOPSIS
    Audits Windows Services for suspicious configurations, hijacked paths, and indicators of compromise.

.DESCRIPTION
    This script retrieves all registered Windows services on the local machine and evaluates 
    them against a series of heuristic security checks to identify potential malware, 
    persistence mechanisms, or misconfigurations. 

    It analyzes service binaries for missing digital signatures, non-existent files, 
    and execution from user-writable directories (e.g., AppData, Temp). It also checks 
    for unquoted service paths (a common privilege escalation vector), blank descriptions, 
    and known-bad service names associated with malware. Services are scored based on 
    the number of matched indicators and presented in descending order of suspicion.

    An optional '$enableExtraChecks' variable can be toggled in the script to enable 
    stricter, higher false-positive checks (e.g., short names, high-entropy random names, 
    and script-based file extensions).
#>

$hostname = $env:computername
$enableExtraChecks = $False

# ── Helpers ──────────────────────────────────────────────────────────────────

function ExtractBinaryPath($pathName) {
    if ([string]::IsNullOrWhiteSpace($pathName)) { return $null }
    $p = $pathName.Trim()
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 1) { return $p.Substring(1, $end - 1) }
        return $p.Trim('"')
    }
    # Unquoted: walk segments until we find an existing file
    $parts = $p -split '\s+'
    $candidate = ""
    foreach ($part in $parts) {
        $candidate = if ($candidate) { "$candidate $part" } else { $part }
        if (Test-Path $candidate -PathType Leaf) { return $candidate }
    }
    # Fallback: first token
    return ($p -split '\s+')[0]
}

function IsSuspiciousPath($path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $true }
    $patterns = @(
        'C:\Users\*',
        'C:\Temp\*',
        'C:\Windows\Temp\*',
        '*\AppData\*',
        '*\Downloads\*',
        '*\Desktop\*',
        '*\$Recycle.Bin\*',
        'C:\PerfLogs\*'
    )
    foreach ($pat in $patterns) {
        if ($path -like $pat) { return $true }
    }
    return $false
}

function IsUnsigned($path) {
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path $path -PathType Leaf)) { return $true }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
        return ($sig.Status -ne "Valid")
    } catch {
        return $true
    }
}

function CalculateEntropy($input) {
    if ([string]::IsNullOrWhiteSpace($input)) { return 0 }
    $chars = $input.ToCharArray()
    $len = $chars.Length
    $freq = @{}
    foreach ($c in $chars) { $freq[$c]++ }
    [double]$entropy = 0
    foreach ($f in $freq.Values) {
        $p = $f / $len
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return $entropy
}

function IsHighEntropyName($name) {
    return ((CalculateEntropy $name) -gt 3.5)
}

function HasSuspiciousExtension($path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $bad = @('.vbs', '.js', '.bat', '.cmd', '.scr', '.ps1', '.hta', '.wsf', '.wsh')
    return ($bad -contains ([IO.Path]::GetExtension($path)))
}

function HasUnquotedSpacePath($rawPath) {
    if ([string]::IsNullOrWhiteSpace($rawPath)) { return $false }
    $p = $rawPath.Trim()
    if ($p.StartsWith('"')) { return $false }
    # Unquoted path with spaces before .exe is exploitable
    $exeIdx = $p.ToLower().IndexOf('.exe')
    if ($exeIdx -lt 0) { return $false }
    $beforeExe = $p.Substring(0, $exeIdx)
    return ($beforeExe.Contains(' '))
}

$KnownBadServiceNames = @(
    'mssecsvc', 'mssecsvr', 'WerFaultSvc', 'javamtsup', 'gaborern',
    'hdlocker', 'RuntimeBrokerSvc', 'windowsdefenderupdater', 'sysmon64',
    'defragsrv', 'microsoftedgeupdater', 'wlogin', 'taskhosting'
)

# ── Main ─────────────────────────────────────────────────────────────────────

Write-Host "[$hostname] Scanning services..." -ForegroundColor Cyan

try {
    $AllServices = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
} catch {
    $AllServices = Get-WmiObject -Class Win32_Service
}

$results = [System.Collections.ArrayList]::new()

foreach ($svc in $AllServices) {
    $reasons = [System.Collections.ArrayList]::new()
    $rawPath = $svc.PathName
    $binPath = ExtractBinaryPath $rawPath

    # ── Always-on checks ────────────────────────────────────────────────

    if (IsSuspiciousPath $binPath) {
        $reasons.Add("Suspicious binary path") | Out-Null
    }

    if ($svc.StartName -eq "LocalSystem") {
        $reasons.Add("Runs as LocalSystem") | Out-Null
    }

    if ([string]::IsNullOrEmpty($svc.Description)) {
        $reasons.Add("No description") | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($rawPath)) {
        $reasons.Add("Empty image path") | Out-Null
    }
    elseif ($binPath -and -not (Test-Path $binPath -PathType Leaf)) {
        $reasons.Add("Binary not found on disk") | Out-Null
    }

    if (IsUnsigned $binPath) {
        $reasons.Add("Unsigned or invalid signature") | Out-Null
    }

    if (HasUnquotedSpacePath $rawPath) {
        $reasons.Add("Unquoted service path (hijack risk)") | Out-Null
    }

    $nameLower = $svc.Name.ToLower()
    foreach ($bad in $KnownBadServiceNames) {
        if ($nameLower -eq $bad.ToLower()) {
            $reasons.Add("Matches known-bad service name") | Out-Null
            break
        }
    }

    # ── Extra checks (more false-positive prone) ────────────────────────

    if ($enableExtraChecks) {
        if ($svc.Name.Length -le 5) {
            $reasons.Add("Very short service name") | Out-Null
        }
        if ($svc.DisplayName.Length -le 5) {
            $reasons.Add("Very short display name") | Out-Null
        }
        if (IsHighEntropyName $svc.Name) {
            $reasons.Add("High-entropy service name") | Out-Null
        }
        if (IsHighEntropyName $svc.DisplayName) {
            $reasons.Add("High-entropy display name") | Out-Null
        }
        if (HasSuspiciousExtension $binPath) {
            $reasons.Add("Suspicious file extension") | Out-Null
        }
    }

    if ($reasons.Count -gt 0) {
        $results.Add([PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            State       = $svc.State
            StartName   = $svc.StartName
            BinaryPath  = $binPath
            RawPath     = $rawPath
            Description = $svc.Description
            Reasons     = $reasons
            FlagCount   = $reasons.Count
        }) | Out-Null
    }
}

# ── Output ───────────────────────────────────────────────────────────────────

if ($results.Count -eq 0) {
    Write-Host "[$hostname] No suspicious services detected." -ForegroundColor Green
    return
}

# Sort by number of flags descending so the most suspicious appear first
$results = $results | Sort-Object -Property FlagCount -Descending

Write-Host ""
Write-Host "[$hostname] Suspicious Services Detected: $($results.Count)" -ForegroundColor Yellow
Write-Host ("=" * 70) -ForegroundColor Yellow

foreach ($r in $results) {
    $color = if ($r.FlagCount -ge 4) { "Red" } elseif ($r.FlagCount -ge 2) { "Yellow" } else { "White" }

    Write-Host "[$hostname] $($r.Name)  ($($r.DisplayName))  [$($r.State)]  Flags: $($r.FlagCount)" -ForegroundColor $color
    Write-Host "  Account : $($r.StartName)" -ForegroundColor Gray
    Write-Host "  Path    : $($r.RawPath)" -ForegroundColor Gray
    foreach ($reason in $r.Reasons) {
        Write-Host "    - $reason" -ForegroundColor $color
    }
    Write-Host ""
}

Write-Host ("=" * 70) -ForegroundColor Yellow
Write-Host "[$hostname] Total flagged: $($results.Count)  |  Critical (4+): $(($results | Where-Object { $_.FlagCount -ge 4 }).Count)  |  Warning (2-3): $(($results | Where-Object { $_.FlagCount -ge 2 -and $_.FlagCount -lt 4 }).Count)  |  Low (1): $(($results | Where-Object { $_.FlagCount -eq 1 }).Count)" -ForegroundColor Cyan
