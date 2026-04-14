<#
.SYNOPSIS
    Audits local SMB shares for insecure permissions and suspicious directory paths, with an option to auto-remediate.

.DESCRIPTION
    This script enumerates all Server Message Block (SMB) shares on the local Windows system 
    to identify potential security risks. It specifically checks for overly permissive access 
    rights (e.g., 'Full' or 'Change' permissions granted to 'Everyone', 'ANONYMOUS LOGON', 
    or 'Authenticated Users') and flags shares that expose sensitive or temporary system 
    directories (like C:\Users or C:\Windows\Temp). 
    
    If executed with the '-Fix' switch, the script will actively remediate these vulnerabilities 
    by automatically revoking the dangerous access control entries (ACEs) from custom (non-built-in) 
    shares. Built-in administrative and system shares (like C$, ADMIN$, or IPC$) are audited for 
    visibility but are explicitly skipped during the automated remediation process to prevent 
    system instability.
#>

param(
    [switch]$Fix
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "         Audit-Shares" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
    Write-Host "Get-SmbShare not available on this OS version." -ForegroundColor Red; exit 1
}

$builtinShares   = @('ADMIN$','IPC$','C$','D$','E$','F$','G$','H$','PRINT$','SYSVOL','NETLOGON','FAX$')
$dangerousNames  = @('Everyone','ANONYMOUS LOGON','NT AUTHORITY\Authenticated Users','Authenticated Users')
$suspiciousPaths = 'C:\\Users|C:\\Temp|C:\\Windows\\Temp|\$RECYCLE|C:\\ProgramData\\Temp'

$totalFlagged = 0
$shares = Get-SmbShare -ErrorAction SilentlyContinue

foreach ($share in $shares) {
    $isBuiltin = $share.Name -in $builtinShares
    $color     = if ($isBuiltin) { "DarkGray" } else { "Cyan" }
    $tag       = if ($isBuiltin) { " [built-in]" } else { "" }

    Write-Host "Share: $($share.Name)$tag   Path: $($share.Path)" -ForegroundColor $color

    $perms = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
    foreach ($perm in $perms) {
        $isDangerous = ($dangerousNames | Where-Object { $perm.AccountName -like "*$_*" }) `
                       -and ($perm.AccessRight -in @('Full','Change'))
        $permColor = if ($isDangerous) { "Red" }    else { "White" }
        $marker    = if ($isDangerous) { " [DANGEROUS]" } else { "" }
        Write-Host "  $($perm.AccountName): $($perm.AccessRight)$marker" -ForegroundColor $permColor

        if ($isDangerous) {
            $totalFlagged++
            if ($Fix -and -not $isBuiltin) {
                Revoke-SmbShareAccess -Name $share.Name -AccountName $perm.AccountName -Force -ErrorAction SilentlyContinue
                Write-Host "  [-] Revoked $($perm.AccountName) on $($share.Name)" -ForegroundColor Yellow
            }
        }
    }

    if ($share.Path -match $suspiciousPaths) {
        Write-Host "  [!] Suspicious share path" -ForegroundColor Red
        $totalFlagged++
    }
    Write-Host ""
}

$flagColor = if ($totalFlagged -gt 0) { "Red" } else { "Green" }
Write-Host "[*] Total flagged issues: $totalFlagged" -ForegroundColor $flagColor

if ($totalFlagged -gt 0 -and -not $Fix) {
    Write-Host "[*] Re-run with -Fix to revoke dangerous ACEs from non-built-in shares." -ForegroundColor Yellow
}
