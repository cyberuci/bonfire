<#
.SYNOPSIS
    Clears PowerShell session history, PSReadLine history, and the system Recycle Bin.

.DESCRIPTION
    This script performs a quick environmental cleanup to remove traces of executed 
    commands and deleted files. It clears the current console screen, wipes the in-memory 
    command history, forcefully deletes the contents of the PSReadLine history file saved 
    on disk, and empties the Windows Recycle Bin without prompting for confirmation.
#>

try {
    Clear-Host
    Clear-History
    Clear-Content -Path (Get-PSReadlineOption).HistorySavePath -Force
    Clear-RecycleBin -Force

    Write-Host "History cleared" -ForegroundColor Green
}
catch {
    Write-Host "Failed to Clear History $_" -ForegroundColor Red
}