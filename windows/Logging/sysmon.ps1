$sysmonPath = "C:\Users\Administrator\Documents\Sysinternals\Sysmon64.exe" 
$configUrl = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$configPath = "C:\Sysinternals\sysmonconfig.xml"

if (!(Test-Path $sysmonPath)) {
    Write-Error "Could not find Sysmon64.exe at $sysmonPath. Please update the path in the script."
    return
}

Invoke-WebRequest -Uri $configUrl -OutFile $configPath

Write-Host "[*] Installing Sysmon..." -ForegroundColor Cyan

Start-Process -FilePath $sysmonPath -ArgumentList "-i `"$configPath`"", "-accepteula" -Wait

Write-Host "Sysmon installed and running with detection rules" -ForegroundColor Green