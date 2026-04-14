<#
.SYNOPSIS
    Exports and backs up all DNS server zones to a specified directory.

.DESCRIPTION
    This script automates the backup of all DNS zones hosted on a Windows DNS Server. 
    It retrieves a list of all active zones, exports each zone's records to a file 
    using 'Export-DnsServerZone' (which defaults to the C:\Windows\System32\dns\ directory), 
    and then moves the resulting .dns files to a designated secure backup folder. 
    Each backup file is appended with a timestamp to maintain a clean history and prevent overwriting.
    
    Prerequisites: This script must be run with Administrator privileges on a Windows 
    Server with the DNS Server role installed.
#>

$secureBackupPath = "C:\Users\Administrator\Documents\dns"

if (!(Test-Path -Path $secureBackupPath)) {
    New-Item -Path $secureBackupPath -ItemType Directory -Force
}

# Get all DNS zones on the server
$zones = Get-DnsServerZone

foreach ($zone in $zones) {
    try {
        $zoneName = $zone.ZoneName
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFileName = "${zoneName}_backup_$timestamp.dns"
        $tempFilePath = "C:\Windows\System32\dns\$backupFileName"
        $finalFilePath = Join-Path $secureBackupPath $backupFileName

        Export-DnsServerZone -Name $zoneName -FileName $backupFileName
        
        Move-Item -Path $tempFilePath -Destination $finalFilePath -Force

        Write-Host "Backed up zone '$zoneName' to '$finalFilePath'" -ForegroundColor Green
    } 
    catch {
        Write-Host "Failed to back up zone '$($zoneName)': $_" -ForegroundColor Red
    }
}

Write-Host "All DNS zones backed up successfully." -ForegroundColor Green
