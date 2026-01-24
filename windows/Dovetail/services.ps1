$hostname = $env:computername

$Error.Clear()
$ErrorActionPreference = "Continue"

# Transcript
try {
    Start-Transcript -Path "C:\Users\Administrator\Documents\transcript_services.txt"
} catch {
    Write-Host "[$($hostname)] Failed to Start Transcript" -ForegroundColor Red
}

# SSH
Write-Host "[$($hostname)] Starting SSH configuration adjustments..." -ForegroundColor Cyan

$sshConfigPath = "C:\ProgramData\ssh\sshd_config"

if (Test-Path $sshConfigPath) {
    Write-Host "[$($hostname)] Found SSH config file at $sshConfigPath. Processing changes..."
    $configLines = Get-Content $sshConfigPath
    $modified = $false
    $newLines = @()
    $pubKeyFound = $false
    $passwordFound = $false

    foreach ($line in $configLines) {
        if ($line -match "^\s*PubKeyAuthentication") {
            $newLines += "PubKeyAuthentication no"
            $pubKeyFound = $true
            $modified = $true
        }
        elseif ($line -match "^\s*PasswordAuthentication") {
            $newLines += "PasswordAuthentication yes"
            $passwordFound = $true
            $modified = $true
        }
        else {
            $newLines += $line
        }
    }

    if (-not $pubKeyFound) {
        $newLines += "PubKeyAuthentication no"
        $modified = $true
    }
    if (-not $passwordFound) {
        $newLines += "PasswordAuthentication yes"
        $modified = $true
    }

    if ($modified) {
        $backupPath = "$sshConfigPath.bak"
        Copy-Item $sshConfigPath $backupPath -Force

        $newLines | Set-Content $sshConfigPath -Force
        Write-Host "[$($hostname)] SSH configuration updated."

        Write-Host "[$($hostname)] Restarting sshd service..."
        Restart-Service sshd -Force
    }
    else {
        Write-Host "[$($hostname)] No changes needed in SSH config."
    }
}
else {
    Write-Host "[$($hostname)] SSH config file not found at $sshConfigPath."
}

# IIS
Write-Host "[$($hostname)] Adjusting IIS settings..." -ForegroundColor Cyan

try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $webdavModule = Get-WebGlobalModule | Where-Object { $_.Name -eq "WebDAVModule" }
} catch {
    Write-Host "[$($hostname)] WebAdministration module not present."
} 

if ($webdavModule) {
    Write-Host "[$($hostname)] WebDAV module found"
    Remove-WebGlobalModule -Name "WebDAVModule"
}
else {
    Write-Host "[$($hostname)] WebDAV module not present."
}

$iisWebRoot = "C:\inetpub\wwwroot"
if (Test-Path $iisWebRoot) {
    icacls $iisWebRoot /reset /T /C
    Write-Host "[$($hostname)] Permissions reset"
}
else {
    Write-Host "[$($hostname)] IIS web root not found at $iisWebRoot."
}

$appPools = Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue
foreach ($pool in $appPools) {
    $currentIdentity = $pool.processModel.identityType
    if ($currentIdentity -ne "ApplicationPoolIdentity") {
        Write-Host "[$($hostname)] Setting ApplicationPoolIdentity for pool: $($pool.Name) (Current: $currentIdentity)"
        Set-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType -Value "ApplicationPoolIdentity"
    }
    else {
        Write-Host "[$($hostname)] Pool $($pool.Name) already uses ApplicationPoolIdentity."
    }
}

# PHP
Write-Host "[$($hostname)] Modifying PHP configuration settings..." -ForegroundColor Cyan

$ConfigFiles = Get-ChildItem -Path "C:\" -Filter "php.ini" -Recurse -ErrorAction SilentlyContinue |
               Select-Object -ExpandProperty FullName

if (-not $ConfigFiles) {
    Write-Host "[$($hostname)] No php.ini files found in the specified folders."
}
else {
    $ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
    $ConfigString_FileUploads        = "file_uploads=off"
    $ConfigString_TrackErrors        = "track_errors = off"
    $ConfigString_HtmlErrors         = "html_errors = off"
    $ConfigString_MaxExecutionTime   = "max_execution_time = 3"
    $ConfigString_DisplayErrors      = "display_errors = off"
    $ConfigString_ShortOpenTag       = "short_open_tag = off"
    $ConfigString_SessionCookieHTTPO = "session.cookie_httponly = 1"
    $ConfigString_SessionUseCookies  = "session.use_only_cookies = 1"
    $ConfigString_SessionCookieSecure= "session.cookie_secure = 1"
    $ConfigString_ExposePhp          = "expose_php = off"
    $ConfigString_MagicQuotesGpc     = "magic_quotes_gpc = off"
    $ConfigString_AllowUrlFopen      = "allow_url_fopen = off"
    $ConfigString_AllowUrlInclude    = "allow_url_include = off"
    $ConfigString_RegisterGlobals    = "register_globals = off"
    $ConfigStrings = @(
        $ConfigString_DisableFuncs,
        $ConfigString_FileUploads,
        $ConfigString_TrackErrors,
        $ConfigString_HtmlErrors,
        $ConfigString_MaxExecutionTime,
        $ConfigString_DisplayErrors,
        $ConfigString_ShortOpenTag,
        $ConfigString_SessionCookieHTTPO,
        $ConfigString_SessionUseCookies,
        $ConfigString_SessionCookieSecure,
        $ConfigString_ExposePhp,
        $ConfigString_MagicQuotesGpc,
        $ConfigString_AllowUrlFopen,
        $ConfigString_AllowUrlInclude,
        $ConfigString_RegisterGlobals
    )

    foreach ($ConfigFile in $ConfigFiles) {
        foreach ($Config in $ConfigStrings) {
            Add-Content -Path $ConfigFile -Value $Config
        }
        Write-Host "[$($hostname)] Configuration updated in $ConfigFile"
        Write-Output "[$($hostname)] Configuration updated in $ConfigFile"
    }

    try {
        iisreset
    } catch {
        Write-Host "[$($hostname)] ISS Reset Failed."
    }
    if (Test-Path "C:\xampp\xampp_stop.exe") {
        & "C:\xampp\xampp_stop.exe"
        Start-Sleep -Seconds 5
        & "C:\xampp\xampp_start.exe"
    } else {
        Write-Host "[$($hostname)] XAMPP installation not found. Skipping XAMPP restart."
    }
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