<#
.SYNOPSIS
    Scans standard Windows autostart execution points (ASEPs) for potentially malicious or unwanted persistence mechanisms.

.DESCRIPTION
    This script audits common Windows persistence locations such as Run/RunOnce registry keys, 
    Startup folders, Winlogon hijack points, AppInit_DLLs, LSA Notification Packages, 
    Image File Execution Options (IFEO) debugger hijacks, and Active Setup StubPaths. 
    
    It evaluates executables configured to run at startup, flagging missing files, unsigned binaries, 
    and unauthorized modifications to critical system keys. The results are categorized as 'Flagged' 
    or 'Clean' and output to the console, with an option to export the full audit log to a CSV file 
    using the -Export parameter.
#>

param(
    [string]$Export
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "            Audit-Autoruns" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$findings = [System.Collections.Generic.List[PSObject]]::new()

function Add-Finding {
    param([string]$Category, [string]$Location, [string]$Name, [string]$Value, [string]$Flag)
    $findings.Add([PSCustomObject]@{
        Category = $Category
        Location = $Location
        Name     = $Name
        Value    = $Value
        Flag     = $Flag
    })
}

function Get-BinaryFlag {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return "empty-value" }
    # Extract bare path, stripping args
    $exe = $CmdLine -replace '^"([^"]+)".*$','$1'
    $exe = $exe     -replace '^(\S+)\s.*$','$1'
    $exe = $exe.Trim()
    if ($exe -eq '') { return $null }
    if (-not (Test-Path $exe -ErrorAction SilentlyContinue)) { return "path-not-found" }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $exe -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') { return "unsigned-or-invalid-sig" }
    } catch { return "sig-check-error" }
    return $null
}

# --- Run / RunOnce keys ---
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    if (-not (Test-Path $key -ErrorAction SilentlyContinue)) { continue }
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    foreach ($p in ($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) {
        Add-Finding "RunKey" $key $p.Name $p.Value (Get-BinaryFlag $p.Value)
    }
}

# --- Startup folders ---
$startupDirs = @(
    [System.Environment]::GetFolderPath('Startup'),
    [System.Environment]::GetFolderPath('CommonStartup')
)
foreach ($dir in $startupDirs) {
    if (-not (Test-Path $dir -ErrorAction SilentlyContinue)) { continue }
    Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Finding "StartupFolder" $dir $_.Name $_.FullName (Get-BinaryFlag $_.FullName)
    }
}

# --- Winlogon Shell / Userinit hijack ---
$wlKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$shell    = (Get-ItemProperty -Path $wlKey -Name "Shell"    -ErrorAction SilentlyContinue).Shell
$userinit = (Get-ItemProperty -Path $wlKey -Name "Userinit" -ErrorAction SilentlyContinue).Userinit

$expectedShell    = "explorer.exe"
$expectedUserinit = "C:\Windows\system32\userinit.exe,"
if ($shell    -and $shell    -ne $expectedShell)    { Add-Finding "Winlogon-Shell"    $wlKey "Shell"    $shell    "MODIFIED" }
if ($userinit -and $userinit -ne $expectedUserinit) { Add-Finding "Winlogon-Userinit" $wlKey "Userinit" $userinit "MODIFIED" }

# --- AppInit_DLLs (should always be empty) ---
$appInitKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
$appInitVal = (Get-ItemProperty -Path $appInitKey -Name "AppInit_DLLs" -ErrorAction SilentlyContinue).AppInit_DLLs
if (-not [string]::IsNullOrWhiteSpace($appInitVal)) {
    Add-Finding "AppInit_DLLs" $appInitKey "AppInit_DLLs" $appInitVal "NONEMPTY-SUSPICIOUS"
}

# --- LSA Notification Packages ---
$lsaKey  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaPkgs = (Get-ItemProperty -Path $lsaKey -Name "Notification Packages" -ErrorAction SilentlyContinue)."Notification Packages"
$knownLsa = @('scecli','rassfm','wdigest','kdcsvc','msv1_0')
foreach ($pkg in $lsaPkgs) {
    if ($pkg -and $pkg -notin $knownLsa) {
        Add-Finding "LSA-NotifyPkg" $lsaKey "Notification Packages" $pkg "UNEXPECTED"
    }
}

# --- Image File Execution Options (debugger hijack) ---
$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoKey -ErrorAction SilentlyContinue) {
    Get-ChildItem -Path $ifeoKey -ErrorAction SilentlyContinue | ForEach-Object {
        $dbg = (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($dbg) {
            Add-Finding "IFEO-Debugger" $_.PSPath $_.PSChildName $dbg "DEBUGGER-HIJACK"
        }
    }
}

# --- ActiveSetup StubPaths ---
$asKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"
if (Test-Path $asKey -ErrorAction SilentlyContinue) {
    Get-ChildItem -Path $asKey -ErrorAction SilentlyContinue | ForEach-Object {
        $stub = (Get-ItemProperty -Path $_.PSPath -Name "StubPath" -ErrorAction SilentlyContinue).StubPath
        if ($stub) {
            $flag = Get-BinaryFlag $stub
            if ($flag) { Add-Finding "ActiveSetup" $_.PSPath $_.PSChildName $stub $flag }
        }
    }
}

# --- Output ---
Write-Host ""
$flagged = @($findings | Where-Object { $_.Flag })
$clean   = @($findings | Where-Object { -not $_.Flag })
Write-Host "[*] Total entries: $($findings.Count)  |  Flagged: $($flagged.Count)  |  Clean: $($clean.Count)" -ForegroundColor Cyan
Write-Host ""

if ($flagged.Count -gt 0) {
    Write-Host "=== FLAGGED ENTRIES ===" -ForegroundColor Red
    $flagged | Format-Table Category, Name, Flag, Value -AutoSize | Out-String | Write-Host -ForegroundColor Red
}
if ($clean.Count -gt 0) {
    Write-Host "=== CLEAN ENTRIES ===" -ForegroundColor Green
    $clean | Format-Table Category, Name, Value -AutoSize | Out-String | Write-Host -ForegroundColor Green
}

if ($Export) {
    $findings | Export-Csv -Path $Export -NoTypeInformation
    Write-Host "[+] Results exported to $Export" -ForegroundColor Cyan
}
