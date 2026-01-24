$backupDir = "C:\CA_Backup"

# Ensure folder exists
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Backup database + config + private key
certutil -backup $backupDir

Write-Host "AD CS backup completed at $backupDir"