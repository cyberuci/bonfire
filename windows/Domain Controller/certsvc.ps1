<#
.SYNOPSIS
Enables Extended Protection for Authentication (EPA) on Windows for security hardening.
.DESCRIPTION
  Configures Windows Extended Protection for Authentication by setting required registry values.
  This enhances protection against authentication relay and "man in the middle" attacks by
  binding authentication requests to Service Principal Names (SPNs) and TLS channels.
  REQUIREMENTS:
    - PowerShell: 5.1+ or 7.x
    - OS: Windows 10/11, Windows Server 2016+
    - Modules: Microsoft.PowerShell.Management (built-in)
  WARNINGS:
    - Requires admin privileges; modifies security-critical registry settings.
    - System restart required after configuration changes.
    - May impact applications not compatible with EPA or NTLMv2.
.EXECUTION
  Run in an elevated PowerShell console.
.NOTES
  VERSION: 1.0
  CHANGELOG:
    - 1.0 (2025-9-15): Initial release.
  DISCLAIMER:
    VICARIUS STRONGLY RECOMMENDS RUNNING THIS SCRIPT IN A TEST LAB ENVIRONMENT
    BEFORE DEPLOYING THEM TO PRODUCTION. USE AT YOUR OWN DISCRETION ONLY AFTER
    CAREFULLY ANALYZING THE CODE.
.AUTHOR
This script has been made by Vicarius Research Team
.VERSION
1.0
#>

# ==========================================
# TAG CONFIGURATION
# ==========================================
$TagInfo = "[Info]"
$TagWarn = "[Warning]"
$TagErr  = "[Error]"

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info","Warning","Error")][string]$Level = "Info"
    )
    $tag = switch ($Level) {
        "Info"    { $TagInfo }
        "Warning" { $TagWarn }
        "Error"   { $TagErr }
    }
    Write-Host "$tag $Message"
}

Write-Status "Require Cert Approval" "Info"
Write-Status "----------------------------------------------------" "Info"

# Get AD config path
$root = Get-ADRootDSE
$configNC = $root.configurationNamingContext

# Path to certificate templates container
$templatesPath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

# Load all template objects
$templates = Get-ADObject -SearchBase $templatesPath -Filter * -Properties msPKI-Enrollment-Flag

$PEND_FLAG = 2

foreach ($tpl in $templates) {
    try {
        $tplName = $tpl.Name
        $currentFlag = [int]$tpl.'msPKI-Enrollment-Flag'

        Write-Host "Processing template: $tplName" -ForegroundColor Yellow
        Write-Host "  Current Flags: $currentFlag"

        # Bind ADSI object
        $tplADSI = [ADSI]"LDAP://$($tpl.DistinguishedName)"

        # Add the pending flag (2nd line UNDOS)
        $newFlags = $currentFlag -bor $PEND_FLAG # TO HARDEN
        # $newFlags = ($currentFlag -band (-bnot $PEND_FLAG)) # TO UNDO


        $tplADSI.'msPKI-Enrollment-Flag' = $newFlags
        $tplADSI.SetInfo()

        Write-Host "  Updated Flags: $newFlags" -ForegroundColor Green
        Write-Host "  CA certificate manager approval ENABLED"
    }
    catch {
        Write-Host "  ERROR modifying template $tplName : $_" -ForegroundColor Red
    }
}

Write-Host "`nAll templates processed." -ForegroundColor Cyan


Write-Status "Enable Extended Protection for Authentication (EPA)" "Info"
Write-Status "----------------------------------------------------" "Info"

# Admin check
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "Administrator privileges required." "Error"
        exit 1
    }
} catch {
    Write-Status "Unable to verify elevation: $($_.Exception.Message)" "Warning"
}

# Registry path and values
$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$EPAKey = "SuppressExtendedProtection"
$LMKey = "LmCompatibilityLevel"
$EPAValue = 0  # 0 enables Extended Protection
$LMValue = 3   # 3 enables NTLMv2 only (minimum requirement for EPA)

# Configure SuppressExtendedProtection
try {
    if (Test-Path $RegPath) {
        $currentEPA = Get-ItemProperty -Path $RegPath -Name $EPAKey -ErrorAction SilentlyContinue
        
        if ($null -eq $currentEPA) {
            Write-Status "Creating $EPAKey registry value..." "Info"
            New-ItemProperty -Path $RegPath -Name $EPAKey -Value $EPAValue -PropertyType DWORD -ErrorAction Stop | Out-Null
        } elseif ($currentEPA.$EPAKey -ne $EPAValue) {
            Write-Status "Updating $EPAKey registry value..." "Info"
            Set-ItemProperty -Path $RegPath -Name $EPAKey -Value $EPAValue -ErrorAction Stop
        } else {
            Write-Status "$EPAKey already set to correct value ($EPAValue)." "Info"
        }
    } else {
        Write-Status "Registry path $RegPath not found." "Error"
        exit 1
    }
} catch {
    Write-Status "Failed to configure ${EPAKey}: $($_.Exception.Message)" "Error"
}

# Configure LmCompatibilityLevel
try {
    $currentLM = Get-ItemProperty -Path $RegPath -Name $LMKey -ErrorAction SilentlyContinue
    
    if ($null -eq $currentLM) {
        Write-Status "Creating $LMKey registry value..." "Info"
        New-ItemProperty -Path $RegPath -Name $LMKey -Value $LMValue -PropertyType DWORD -ErrorAction Stop | Out-Null
    } elseif ($currentLM.$LMKey -lt $LMValue) {
        Write-Status "Updating $LMKey registry value to minimum required level..." "Info"
        Set-ItemProperty -Path $RegPath -Name $LMKey -Value $LMValue -ErrorAction Stop
    } else {
        Write-Status "$LMKey already set to acceptable value ($($currentLM.$LMKey))." "Info"
    }
} catch {
    Write-Status "Failed to configure ${LMKey}: $($_.Exception.Message)" "Error"
}

# Verify configuration
try {
    $verifyEPA = Get-ItemProperty -Path $RegPath -Name $EPAKey -ErrorAction Stop
    $verifyLM = Get-ItemProperty -Path $RegPath -Name $LMKey -ErrorAction Stop
    
    if ($verifyEPA.$EPAKey -eq $EPAValue) {
        Write-Status "Extended Protection successfully enabled ($EPAKey = $EPAValue)." "Info"
    } else {
        Write-Status "Verification failed: $EPAKey value is '$($verifyEPA.$EPAKey)'." "Error"
    }
    
    if ($verifyLM.$LMKey -ge $LMValue) {
        Write-Status "LM Compatibility Level properly configured ($LMKey = $($verifyLM.$LMKey))." "Info"
    } else {
        Write-Status "Verification failed: $LMKey value is '$($verifyLM.$LMKey)'." "Error"
    }
} catch {
    Write-Status "Could not verify EPA configuration: $($_.Exception.Message)" "Warning"
}

Write-Status "Extended Protection for Authentication configuration completed." "Info"
Write-Status "System restart required for changes to take effect." "Warning"

Write-Host "`nModifying AttributeSubjectAltName" -ForegroundColor Cyan
try {
    certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
    net stop certsvc; net start certsvc
    Write-Host "Certificate Services modified successfully." -ForegroundColor Green
} catch {
    Write-Host "Failed to modify Certificate Services: $_" -ForegroundColor Red
}

Write-Host "`nSetting CertificateMappingMethods" -ForegroundColor Cyan
$regPath = "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Schannel"
$regName = "CertificateMappingMethods"
$newValue = 0x0018   # decimal 24

# Ensure key exists (New-Item -Force does not overwrite existing keys)
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Check if value exists
$current = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
try {
    if ($current) {
        Write-Host "Value exists. Updating $regName" -ForegroundColor Yellow
        Set-ItemProperty -Path $regPath -Name $regName -Value $newValue -Type DWord
        Write-Host "$regName updated successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Value does not exist. Creating $regName" -ForegroundColor Yellow
        New-ItemProperty -Path $regPath -Name $regName -Value $newValue -PropertyType DWord -Force
        Write-Host "$regName created successfully." -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to set ${regName}: $_" -ForegroundColor Red
}


Write-Host "`nSetting StrongCertificateBindingEnforcement" -ForegroundColor Cyan
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"
$regName = "StrongCertificateBindingEnforcement"
$newValue = 2   # DWORD

# Ensure key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Check if value exists
$current = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
try {
    if ($current) {
        Write-Host "Value exists. Updating $regName" -ForegroundColor Yellow
        Set-ItemProperty -Path $regPath -Name $regName -Value $newValue -Type DWord
        Write-Host "$regName updated successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Value does not exist. Creating $regName" -ForegroundColor Yellow
        New-ItemProperty -Path $regPath -Name $regName -Value $newValue -PropertyType DWord -Force
        Write-Host "$regName created successfully." -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to set ${regName}: $_" -ForegroundColor Red
}

