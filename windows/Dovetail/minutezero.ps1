# Local Subnets (X.X.X.0/24) (keep blank if none)
$localsubnet1 = ""
$localsubnet2 = ""

$blockedPorts = 

$hostname = $env:computername

# Validate Input
if ($localsubnet1 -notmatch '^(\d{1,3}\.){3}0/(\d{1,2})$') {
    Write-Host("[$($hostname)] Invalid subnet 1. Enter in the form X.X.X.0/24") -ForegroundColor Red
    return
}

if ($localsubnet2 -ne "" -and $localsubnet2 -notmatch '^(\d{1,3}\.){3}0/(\d{1,2})$') {
    Write-Host("[$($hostname)] Invalid subnet 2. Enter in the form X.X.X.0/24") -ForegroundColor Red
    return
}

$Error.Clear()
$ErrorActionPreference = "Continue"

# Transcript
try {
    Start-Transcript -Path "C:\Users\Administrator\Documents\transcript_minutezero.txt"
} catch {
    Write-Host "[$($hostname)] Failed to Start Transcript" -ForegroundColor Red
}

# SMB
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "[$($hostname)] SMBv1 disabled via Set-SmbServerConfiguration." -ForegroundColor Green
} catch {
    Write-Host "[$($hostname)] Failed to disable SMBv1 using Set-SmbServerConfiguration (not available on some OS versions)." -ForegroundColor Red
}

# Print Spooler
try {
    Stop-Service -Name "Spooler" -ErrorAction Stop
    Set-Service -Name "Spooler" -StartupType Disabled
    Write-Host "[$($hostname)] Print Spooler service has been disabled." -ForegroundColor Green
}
catch {
    Write-Host "[$($hostname)] Failed to disable Print Spooler service: $_" -ForegroundColor Red
}

# DC Minute 0
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    $outputFilePath = "C:\Users\Administrator\Documents\undo_deprivileges.txt"
    Add-Content -Path $outputFilePath -Value " "
    Add-Content -Path $outputFilePath -Value "# Undo Deprivileges"

    $groups = @("Domain Admins", "Enterprise Admins", "Administrators", "DnsAdmins", "Group Policy Creator Owners", "Schema Admins", "Key Admins", "Enterprise Key Admins")

    foreach ($group in $groups) {
        $excludedSamAccountNames = @("Administrator", "Domain Admins", "Enterprise Admins")

        $members = Get-ADGroupMember -Identity $group | Where-Object {
            $excludedSamAccountNames -notcontains $_.SamAccountName
        }

        foreach ($member in $members) {
            try {
                Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
                Write-Host "[$($hostname)] Removed $($member.SamAccountName) from $group."
                Write-Output "[$($hostname)] Removed $($member.SamAccountName) from $group."
                Add-Content -Path $outputFilePath -Value "Add-ADGroupMember -Identity '$($group)' -Members '$($member.SamAccountName)';"
            }
            catch {
                Write-Host "[$($hostname)] Failed to remove group member $($member.SamAccountName) from $($group): $_" -ForegroundColor Red
            }
        }
    }

    try {
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Write-Host "[$($hostname)] Kerberos Pre-authentication enabled for applicable users." -ForegroundColor Green
    }
    catch {
        Write-Host "[$($hostname)] Failed to enable Kerberos Pre-authentication: $_" -ForegroundColor Red
    }

    try {
        $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
        Disable-ADAccount -Identity $guestAccount.SamAccountName
        Write-Host "[$($hostname)] Guest account has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "[$($hostname)] Failed to disable Guest account: $_" -ForegroundColor Red
    }

    try {
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        Write-Host "[$($hostname)] FullSecureChannelProtection enabled." -ForegroundColor Green

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        $regName = "vulnerablechannelallowlist"
        if (Test-Path -Path "$regPath\$regName") {
            Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
            Write-Host "[$($hostname)] vulnerablechannelallowlist removed." -ForegroundColor Green
        } else {
            Write-Host "[$($hostname)] vulnerablechannelallowlist does not exist, no action needed." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[$($hostname)] Failed to apply Zerologon mitigation: $_" -ForegroundColor Red
    }

    try {
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota" = "0" } | Out-Null
        Write-Host "[$($hostname)] ms-DS-MachineAccountQuota set to 0." -ForegroundColor Green
    }
    catch {
        Write-Host "[$($hostname)] Failed to apply noPac mitigation: $_" -ForegroundColor Red
    }
}

# Firewall
netsh a s a state off 
netsh a s a firewallpolicy "allowinbound,blockoutbound"
netsh a f de r n=all 

netsh a f a r n="RDP" dir=in a=allow prot=TCP localport=3389 

netsh a f a r n="Local_TCP_In" dir=in a=allow prot=TCP remoteip=$localsubnet1 
netsh a f a r n="Local_UDP_In" dir=in a=allow prot=UDP remoteip=$localsubnet1 
netsh a f a r n="ICMP_In" dir=in a=allow prot=ICMPv4
netsh a f a r n="Local_TCP_Out" dir=out a=allow prot=TCP remoteip=$localsubnet1 
netsh a f a r n="Local_UDP_Out" dir=out a=allow prot=UDP remoteip=$localsubnet1 
netsh a f a r n="ICMP_Out" dir=out a=allow prot=ICMPv4
Write-Host "[$($hostname)] Localsubnet1: $($localsubnet1)" -ForegroundColor Cyan

if ($localsubnet2 -ne "") {
    netsh a f a r n="Local2_TCP_In" dir=in a=allow prot=TCP remoteip=$localsubnet2 
    netsh a f a r n="Local2_UDP_In" dir=in a=allow prot=UDP remoteip=$localsubnet2 
    netsh a f a r n="Local2_TCP_Out" dir=out a=allow prot=TCP remoteip=$localsubnet2 
    netsh a f a r n="Local2_UDP_Out" dir=out a=allow prot=UDP remoteip=$localsubnet2 
    Write-Host "[$($hostname)] Localsubnet2: $($localsubnet2)" -ForegroundColor Cyan
}

# DC Firewall
if (Get-WmiObject -Query "select * from Win32_OperatingSystem where ProductType='2'") {
    netsh a f a r n="DNS_Out" dir=out a=allow program="%SystemRoot%\System32\dns.exe"
    netsh a f a r n="DNS_In" dir=in a=allow prot=UDP localport=53 
}

# Initial Blocks
if ($localsubnet2 -eq "") {
    $s = $localsubnet1.Split('.')
    $prev = "$($s[0]).$($s[1]).$([int]$s[2] - 1).255"
    $next = "$($s[0]).$($s[1]).$([int]$s[2] + 1).1"

    netsh a f a r n="Block_Below" dir=in a=block prot=TCP remoteip=0.0.0.0-$($prev) localport=$($blockedPorts) > $null
    netsh a f a r n="Block_Above" dir=in a=block prot=TCP remoteip=$($next)-255.255.255.255 localport=$($blockedPorts) > $null
    Write-Host "[$($hostname)] Blocks: (0.0.0.0 - $($prev)), ($($next) - 255.255.255.255)" -ForegroundColor Cyan

} else {
    $s1 = $localsubnet1.Split('.')
    $s2 = $localsubnet2.Split('.')

    if (
        ($s1[0] -lt $s2[0]) -or
        ($s1[0] -eq $s2[0] -and $s1[1] -lt $s2[1]) -or
        ($s1[0] -eq $s2[0] -and $s1[1] -eq $s2[1] -and $s1[2] -lt $s2[2]) -or
        ($s1[0] -eq $s2[0] -and $s1[1] -eq $s2[1] -and $s1[2] -eq $s2[2] -and $s1[3] -le $s2[3])
    ) {
        # Localsubnet1 is lower
        $prev1 = "$($s1[0]).$($s1[1]).$([int]$s1[2] - 1).255"
        $next1 = "$($s1[0]).$($s1[1]).$([int]$s1[2] + 1).1"
        $prev2 = "$($s2[0]).$($s2[1]).$([int]$s2[2] - 1).255"
        $next2 = "$($s2[0]).$($s2[1]).$([int]$s2[2] + 1).1"
    } else {
        # Localsubet2 is lower
        $prev2 = "$($s1[0]).$($s1[1]).$([int]$s1[2] - 1).255"
        $next2 = "$($s1[0]).$($s1[1]).$([int]$s1[2] + 1).1"
        $prev1 = "$($s2[0]).$($s2[1]).$([int]$s2[2] - 1).255"
        $next1 = "$($s2[0]).$($s2[1]).$([int]$s2[2] + 1).1"
    }

    netsh a f a r n="Block_Below" dir=in a=block prot=TCP remoteip=0.0.0.0-$($prev1) localport=$($blockedPorts) 
    netsh a f a r n="Block_Between" dir=in a=block prot=TCP remoteip=$($next1)-$($prev2) localport=$($blockedPorts) 
    netsh a f a r n="Block_Above" dir=in a=block prot=TCP remoteip=$($next2)-255.255.255.255 localport=$($blockedPorts) 
    Write-Host "[$($hostname)] Blocks: (0.0.0.0 - $($prev1)), ($($next1) - $($prev2)), ($($next2) - 255.255.255.255)" -ForegroundColor Cyan
}

# Logging
netsh a s a logging allowedconnections enable
netsh a s a logging droppedconnections enable
netsh a s a logging filename "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
netsh a s a logging maxfilesize 10000

netsh a s a state on 

# Defender
if (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue) {
    try {
        Start-Service -Name WinDefend -ErrorAction Stop
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
        Write-Host "[$($hostname)] Started Windows Defender" -ForegroundColor Green
    } catch {
        Write-Host "[$($hostname)] Failed to start Windows Defender: $_" -ForegroundColor Red
    }

    try {
        $mpPrefs = Get-MpPreference

        if ($mpPrefs.ExclusionProcess) { 
            Remove-MpPreference -ExclusionProcess $mpPrefs.ExclusionProcess 
        }
        if ($mpPrefs.ExclusionPath) { 
            Remove-MpPreference -ExclusionPath $mpPrefs.ExclusionPath 
        }
        if ($mpPrefs.ExclusionExtension) { 
            Remove-MpPreference -ExclusionExtension $mpPrefs.ExclusionExtension 
        }

        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "[$($hostname)] Set DisableRealtimeMonitoring to False" -ForegroundColor Green
    } catch {
        Write-Host "[$($hostname)] Error configuring Windows Defender: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[$($hostname)] Windows Defender does not exist." -ForegroundColor Red
}

# File Permissions
try {
    takeown /F "C:\Windows\System32\cmd.exe" /A | Out-Null 
    icacls "C:\Windows\System32\cmd.exe" /reset | Out-Null 

    takeown /F "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /A | Out-Null 
    icacls "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /reset | Out-Null 

    takeown /F "C:\Windows\regedit.exe" /A | Out-Null 
    icacls "C:\Windows\regedit.exe" /reset | Out-Null 

    takeown /F "C:\Windows\System32\mmc.exe" /A | Out-Null 
    icacls "C:\Windows\System32\mmc.exe" /reset | Out-Null 

    takeown /F "C:\Windows\System32\wscript.exe" /A | Out-Null 
    icacls "C:\Windows\System32\wscript.exe" /reset | Out-Null 

    takeown /F "C:\Windows\System32\cscript.exe" /A | Out-Null 
    icacls "C:\Windows\System32\cscript.exe" /reset | Out-Null 

    Write-Host "[$($hostname)] File permissions changed" -ForegroundColor Green
} catch {
    Write-Host "[$($hostname)] Failed to change file permissions $_" -ForegroundColor Red
}

# Registry
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null 
    Write-Host "[$($hostname)] PTH Mitigation complete" -ForegroundColor Green
} catch {
    Write-Host "[$($hostname)] Failed to apply PTH mitigation $_" -ForegroundColor Red
}

try {
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 2 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 3 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 6 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v "ForceDefenderPassiveMode" /t REG_DWORD /d 0 /f | Out-Null 
    Write-Host "[$($hostname)] Set Defender options" -ForegroundColor Green
} catch {
    Write-Host "[$($hostname)] Failed to set Defender options: $_" -ForegroundColor Red
}

try {
    $addMpPrefCmd = Get-Command Add-MpPreference -ErrorAction SilentlyContinue
    $defenderService = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($addMpPrefCmd.Parameters.ContainsKey("AttackSurfaceReductionRules_Ids") -and $defenderService.Status -eq "Running") {
        # Block Office applications from injecting code into other processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block Office applications from creating executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block all Office applications from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EfC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block JavaScript or VBScript from launching downloaded executable content
        Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block execution of potentially obfuscated scripts
        Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block executable content from email client and webmail
        Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block Win32 API calls from Office macro
        Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block process creations originating from PSExec and WMI commands
        Add-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D77406C -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block untrusted and unsigned processes that run from USB
        Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Use advanced protection against ransomware
        Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block credential stealing from the Windows local security authority subsystem (lsass.exe)
        Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block Office communication application from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49E8-8B27-EB1D0A1CE869 -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block Adobe Reader from creating child processes
        Add-MpPreference -AttackSurfaceReductionRules_Ids 7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block persistence through WMI event subscription
        Add-MpPreference -AttackSurfaceReductionRules_Ids E6DB77E5-3DF2-4CF1-B95A-636979351E5B -AttackSurfaceReductionRules_Actions Enabled | Out-Null 
        # Block use of copied or impersonated system tools
        Add-MpPreference -AttackSurfaceReductionRules_Ids C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB -AttackSurfaceReductionRules_Actions Enabled | Out-Null 

        Write-Host "[$($hostname)] Defender Attack Surface Reduction rules enabled." -ForegroundColor Green
        ForEach ($ExcludedASR in (Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionOnlyExclusions ) {
            Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null 
        }
    }
    else {
        Write-Host "[$($hostname)] Old defender version detected, skipping ASR rules." -ForegroundColor Cyan
    }
    ForEach ($ExcludedExt in (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionExtension) {
        Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null 
    }
    ForEach ($ExcludedIp in (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionIpAddress) {
        Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null 
    }
    ForEach ($ExcludedDir in (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath) {
        Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null 
    }
    ForEach ($ExcludedProc in (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionProcess) {
        Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null 
    }
} catch {
    Write-Host "[$($hostname)] Failed to enabled ASR Rules: $_" -ForegroundColor Red
}

# UAC
try {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f | Out-Null 
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f | Out-Null 
    Write-Host "[$($hostname)] UAC enabled" -ForegroundColor Green
} catch {
    Write-Host "[$($hostname)] Failed to enable UAC: $_" -ForegroundColor Red
}

# Stop Transcript
try {
    Stop-Transcript
}
catch {
    Write-Host "[$($hostname)] Failed to Stop Transcript" -ForegroundColor Red
}

if ($Error[0]) {
    Write-Output "`n#########################"
    Write-Output "#        ERRORS         #"
    Write-Output "#########################`n"
    foreach ($err in $Error) {
        Write-Output $err
    }
}