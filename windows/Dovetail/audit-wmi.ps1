<#
.SYNOPSIS
    Audits the WMI repository for suspicious event subscriptions and potential persistence mechanisms.

.DESCRIPTION
    This script enumerates the 'root\subscription' WMI namespace to detect malicious 
    Event Filters, Event Consumers, and Filter-to-Consumer Bindings. It compares discovered 
    filters against a list of known-safe Microsoft defaults and highlights unknown entries 
    for review. It specifically flags consumers that are configured to execute command lines, 
    scripts, or discrete binaries. 
    
    If executed with the '-Remove' switch, the script provides an interactive prompt allowing 
    administrators to forcefully delete all enumerated WMI subscriptions to wipe out the 
    persistence mechanisms.
#>

param(
    [switch]$Remove
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "            Audit-WMI" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ns = "root\subscription"

$filters   = Get-WmiObject -Namespace $ns -Class __EventFilter            -ErrorAction SilentlyContinue
$consumers = Get-WmiObject -Namespace $ns -Class __EventConsumer           -ErrorAction SilentlyContinue
$bindings  = Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

# Partial names of known-safe Microsoft filters
$safeFilterNames = @('BVTFilter','TSLogonEvents','TSLogonFilter','RAeFilter',
                     'SCM Event Log Filter','WSCEAA','SensorFramework')

Write-Host ""

# --- Event Filters ---
Write-Host "=== Event Filters ($(@($filters).Count)) ===" -ForegroundColor Cyan
if ($filters) {
    foreach ($f in $filters) {
        $isSafe = $safeFilterNames | Where-Object { $f.Name -like "*$_*" }
        $color  = if ($isSafe) { "DarkGray" } else { "Yellow" }
        $marker = if (-not $isSafe) { "  <-- REVIEW" } else { "" }
        Write-Host "  Name:   $($f.Name)$marker" -ForegroundColor $color
        Write-Host "  Query:  $($f.Query)"        -ForegroundColor $color
        Write-Host ""
    }
} else {
    Write-Host "  (none)" -ForegroundColor Green
}

# --- Event Consumers ---
Write-Host "=== Event Consumers ($(@($consumers).Count)) ===" -ForegroundColor Cyan
if ($consumers) {
    foreach ($c in $consumers) {
        Write-Host "  [$($c.__CLASS)] $($c.Name)" -ForegroundColor Yellow
        if ($c.CommandLineTemplate) { Write-Host "  CommandLine: $($c.CommandLineTemplate)" -ForegroundColor Red }
        if ($c.ScriptText)          { Write-Host "  Script:      $($c.ScriptText)"          -ForegroundColor Red }
        if ($c.ExecutablePath)      { Write-Host "  Executable:  $($c.ExecutablePath)"      -ForegroundColor Red }
        Write-Host ""
    }
} else {
    Write-Host "  (none)" -ForegroundColor Green
}

# --- Bindings ---
Write-Host "=== Filter-to-Consumer Bindings ($(@($bindings).Count)) ===" -ForegroundColor Cyan
if ($bindings) {
    $bindings | ForEach-Object {
        Write-Host "  $($_.Filter) --> $($_.Consumer)" -ForegroundColor Yellow
    }
    Write-Host ""
} else {
    Write-Host "  (none)" -ForegroundColor Green
}

# --- Optional removal ---
$hasData = @($filters).Count -gt 0 -or @($consumers).Count -gt 0 -or @($bindings).Count -gt 0
if ($Remove -and $hasData) {
    Write-Host ""
    $confirm = Read-Host "Remove ALL WMI subscriptions listed above? [y/N]"
    if ($confirm -ieq 'y') {
        @($bindings)  | ForEach-Object {
            try { $_.Delete(); Write-Host "  Removed binding"              -ForegroundColor Green } catch { Write-Host "  Failed binding: $_" -ForegroundColor Red }
        }
        @($consumers) | ForEach-Object {
            try { $_.Delete(); Write-Host "  Removed consumer: $($_.Name)" -ForegroundColor Green } catch { Write-Host "  Failed consumer: $_" -ForegroundColor Red }
        }
        @($filters)   | ForEach-Object {
            try { $_.Delete(); Write-Host "  Removed filter: $($_.Name)"   -ForegroundColor Green } catch { Write-Host "  Failed filter: $_"   -ForegroundColor Red }
        }
    }
} elseif ($Remove) {
    Write-Host "[*] Nothing to remove." -ForegroundColor Green
}
