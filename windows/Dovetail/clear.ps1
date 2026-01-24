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