<#
.SYNOPSIS
    Re-enables Microsoft Defender by removing disabling registry keys, clearing restrictive GPOs, and ensuring the feature is installed.

.DESCRIPTION
    This script is designed to remediate environments where Microsoft Defender has been 
    administratively disabled or uninstalled. It performs several layers of restoration:
    
    1. Feature Restoration: Checks if Defender is installed; if not, it attempts to 
       reinstall the feature on Windows Server (using Install-WindowsFeature) or 
       Windows 10/11 (using DISM/OptionalFeature).
    2. GPO Remediation (DC Only): If run on a Domain Controller, it searches for a 
       specific Group Policy Object (default: "DisableDefender"), removes restrictive 
       registry values within that GPO, and unlinks it from the domain root.
    3. Local Registry Cleanup: Sweeps the local machine for registry overrides that 
       disable real-time monitoring, behavior monitoring, or the core AntiSpyware engine.
    4. Service Enforcement: Forces a Group Policy update, sets the 'WinDefend' service 
       to Automatic startup, and attempts to start the service.
    
    Note: Some changes, particularly feature reinstallation and certain registry 
    reversions, may require a system reboot to take full effect.
#>

#Requires -RunAsAdministrator

$hostname = $env:computername
$GPO_NAME = "DisableDefender"

try {
    $domainRole = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).DomainRole
} catch {
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
}
# DomainRole: 4 = Backup DC, 5 = Primary DC
$IS_DC = $domainRole -ge 4
Write-Host "[$hostname] Running on: $(if ($IS_DC) { 'Domain Controller' } else { 'Member Server/Workstation' })" -ForegroundColor Cyan

$DEFENDER_KEYS = @{
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" = @(
        "DisableAntiSpyware"
        "DisableAntiVirus"
    )
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @(
        "DisableRealtimeMonitoring"
        "DisableBehaviorMonitoring"
        "DisableOnAccessProtection"
        "DisableScriptScanning"
        "DisableIOAVProtection"
    )
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" = @(
        "SpynetReporting"
        "SubmitSamplesConsent"
    )
}

# ── FEATURE REINSTALL (first, so binaries exist before service starts) ────────

Write-Host "[$hostname] Checking Windows Defender feature state..." -ForegroundColor Cyan

if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    $feature = Get-WindowsFeature -Name "Windows-Defender-Features" -ErrorAction SilentlyContinue
    if ($feature -and $feature.InstallState -ne "Installed") {
        Write-Host "[$hostname] Installing Windows-Defender-Features..." -ForegroundColor Yellow
        $result = Install-WindowsFeature -Name "Windows-Defender-Features" -IncludeAllSubFeature
        if ($result.Success) {
            Write-Host "[$hostname] Feature installed successfully" -ForegroundColor Green
            if ($result.RestartNeeded -eq "Yes") {
                Write-Host "[$hostname] WARNING: Reboot required to complete installation" -ForegroundColor Red
            }
        } else {
            Write-Host "[$hostname] Feature install failed" -ForegroundColor Red
        }
    } elseif ($feature) {
        Write-Host "[$hostname] Windows-Defender-Features already installed" -ForegroundColor Green
    } else {
        Write-Host "[$hostname] Windows-Defender-Features not available on this OS" -ForegroundColor Yellow
    }
} elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    # Windows 10/11 workstations use DISM-based cmdlets
    $feature = Get-WindowsOptionalFeature -Online -FeatureName "Windows-Defender" -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -ne "Enabled") {
        Write-Host "[$hostname] Enabling Windows-Defender optional feature..." -ForegroundColor Yellow
        Enable-WindowsOptionalFeature -Online -FeatureName "Windows-Defender" -NoRestart -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[$hostname] Feature enabled (may require reboot)" -ForegroundColor Green
    } elseif ($feature) {
        Write-Host "[$hostname] Windows-Defender feature already enabled" -ForegroundColor Green
    } else {
        Write-Host "[$hostname] Windows-Defender feature not found" -ForegroundColor Yellow
    }
} else {
    Write-Host "[$hostname] Cannot check feature state (no feature management cmdlets)" -ForegroundColor Yellow
}

# ── GPO CLEANUP (DC only) ────────────────────────────────────────────────────

Write-Host ""
if ($IS_DC) {
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        Write-Host "[$hostname] Clearing DisableDefender GPO settings..." -ForegroundColor Cyan

        $gpo = Get-GPO -Name $GPO_NAME -ErrorAction SilentlyContinue
        if ($gpo) {
            foreach ($key in $DEFENDER_KEYS.Keys) {
                foreach ($val in $DEFENDER_KEYS[$key]) {
                    try {
                        Remove-GPRegistryValue -Name $GPO_NAME -Key $key -ValueName $val -ErrorAction Stop | Out-Null
                    } catch {
                        # Value wasn't set
                    }
                }
            }
            Write-Host "[$hostname] GPO registry values cleared" -ForegroundColor Green

            $domain = (Get-ADDomain).DistinguishedName
            $existingLink = (Get-GPInheritance -Target $domain).GpoLinks | Where-Object { $_.DisplayName -eq $GPO_NAME }
            if ($existingLink) {
                Remove-GPLink -Name $GPO_NAME -Target $domain | Out-Null
                Write-Host "[$hostname] GPO domain root link removed" -ForegroundColor Green
            } else {
                Write-Host "[$hostname] No GPO domain root link found" -ForegroundColor Green
            }
        } else {
            Write-Host "[$hostname] GPO '$GPO_NAME' does not exist" -ForegroundColor Green
        }
    } else {
        Write-Host "[$hostname] GroupPolicy module not available, skipping GPO cleanup" -ForegroundColor Yellow
    }
} else {
    Write-Host "[$hostname] Not a DC, skipping GPO cleanup" -ForegroundColor Gray
}

# ── LOCAL REGISTRY CLEANUP (all machines) ─────────────────────────────────────

Write-Host ""
Write-Host "[$hostname] Cleaning local registry overrides..." -ForegroundColor Cyan

foreach ($key in $DEFENDER_KEYS.Keys) {
    $psPath = $key -replace '^HKLM\\', 'HKLM:\'
    if (Test-Path $psPath) {
        foreach ($val in $DEFENDER_KEYS[$key]) {
            $existing = Get-ItemProperty -Path $psPath -Name $val -ErrorAction SilentlyContinue
            if ($null -ne $existing.$val) {
                Remove-ItemProperty -Path $psPath -Name $val -Force -ErrorAction SilentlyContinue
                Write-Host "[$hostname] Removed $psPath\$val" -ForegroundColor Green
            }
        }
    }
}

# Also clear Tamper Protection disable and ForceDefenderPassiveMode
$extraCleanup = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; Name = "ServiceKeepAlive" }
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"; Name = "ForceDefenderPassiveMode" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Name = "DisableAntiSpyware" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Name = "DisableAntiVirus" }
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring" }
)
foreach ($item in $extraCleanup) {
    if (Test-Path $item.Path) {
        $existing = Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
        if ($null -ne $existing.($item.Name)) {
            Remove-ItemProperty -Path $item.Path -Name $item.Name -Force -ErrorAction SilentlyContinue
            Write-Host "[$hostname] Removed $($item.Path)\$($item.Name)" -ForegroundColor Green
        }
    }
}

# ── GPUPDATE ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[$hostname] Running gpupdate..." -ForegroundColor Cyan
gpupdate /force 2>&1 | Out-Null

# ── RESTART SERVICE ───────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[$hostname] Ensuring WinDefend is running..." -ForegroundColor Cyan

$svc = Get-Service WinDefend -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.StartType -ne "Automatic") {
        Set-Service WinDefend -StartupType Automatic
        Write-Host "[$hostname] WinDefend StartupType set to Automatic" -ForegroundColor Green
    } else {
        Write-Host "[$hostname] WinDefend StartupType already Automatic" -ForegroundColor Green
    }

    if ($svc.Status -ne "Running") {
        Start-Service WinDefend -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svc.Refresh()
        if ($svc.Status -eq "Running") {
            Write-Host "[$hostname] WinDefend started" -ForegroundColor Green
        } else {
            Write-Host "[$hostname] WinDefend status: $($svc.Status) (may need reboot)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[$hostname] WinDefend already running" -ForegroundColor Green
    }
} else {
    Write-Host "[$hostname] WinDefend service not found -- feature install likely needs a reboot" -ForegroundColor Red
}

# ── SUMMARY ───────────────────────────────────────────────────────────────────

Write-Host ""
if ($IS_DC) {
    Write-Host "[$hostname] Done. Defender re-enabled via GPO clear (domain-wide) + local registry cleanup + feature install." -ForegroundColor Cyan
} else {
    Write-Host "[$hostname] Done. Defender re-enabled via local registry cleanup + feature install. Run on DC to clear domain-wide GPO." -ForegroundColor Cyan
}
