<#
.SYNOPSIS
    Performs a full backup of Active Directory Certificate Services (AD CS).

.DESCRIPTION
    This script automates the backup process for an AD CS Certification Authority. 
    It ensures the target backup directory exists and uses the 'certutil' command 
    to export the CA database, configuration settings, and the CA's private key.
    
    Prerequisites: This script must be run with Administrator privileges on the 
    Certification Authority server.
#>

#Requires -RunAsAdministrator

$backupDir = "C:\CA_Backup"

Write-Host "Starting AD CS Backup..." -ForegroundColor Cyan

# Ensure folder exists
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Backup database + config + private key
certutil -backup $backupDir

Write-Host "AD CS backup completed at $backupDir" -ForegroundColor Green

$backupDir = "C:\CA_Backup"

# Ensure folder exists
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

# Backup database + config + private key
certutil -backup $backupDir

Write-Host "AD CS backup completed at $backupDir"