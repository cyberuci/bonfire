Write-Host "`nLast 10 Successful and Failed Logins:" -ForegroundColor Cyan

$allLogins = @()

$successLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} -MaxEvents 200 -ErrorAction SilentlyContinue | Where-Object {
    $xml = [xml]$_.ToXml()
    $logonType = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' } | Select-Object -ExpandProperty '#text'
    $targetUser = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' } | Select-Object -ExpandProperty '#text'
    
    # Include Interactive (2), Network (3), and RDP (10), exclude system and computer accounts
    $logonType -in @('2', '3', '10') -and 
    $targetUser -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+)$' -and
    $targetUser -notmatch '\$$'  # Exclude computer accounts (ending in $)
} | Select-Object -First 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $logonType = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    $logonTypeDesc = switch ($logonType) {
        '2'  { 'Interactive' }
        '3'  { 'Network' }
        '10' { 'RDP' }
        default { "Type $logonType" }
    }
    
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Status = 'SUCCESS'
        User = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        Domain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        Reason = $logonTypeDesc
        SourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        Workstation = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    }
}
$allLogins += $successLogins

$failedLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625
} -MaxEvents 10 -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $failureReason = ($eventData | Where-Object { $_.Name -eq 'Status' }).'#text'
    $failureDesc = switch ($failureReason) {
        '0xC0000064' { 'User does not exist' }
        '0xC000006A' { 'Incorrect password' }
        '0xC000006D' { 'Bad username or password' }
        '0xC000006E' { 'Account restriction' }
        '0xC0000071' { 'Password expired' }
        '0xC0000072' { 'Account disabled' }
        '0xC0000073' { 'Logon hours restriction' }
        '0xC0000193' { 'Account expired' }
        '0xC0000224' { 'Password must be changed' }
        '0xC0000234' { 'Account locked out' }
        default { $failureReason }
    }
    
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Status = 'FAILED'
        User = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        Domain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        Reason = $failureDesc
        SourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        Workstation = ($eventData | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    }
}
$allLogins += $failedLogins

$allLogins | Sort-Object Time -Descending | Format-Table -Property Time, Status, User, Domain, Reason, SourceIP, Workstation -Wrap | Out-String -Width 4096 -Stream | ForEach-Object {
    if ($_ -match 'SUCCESS') {
        Write-Host $_ -ForegroundColor Green
    } elseif ($_ -match 'FAILED') {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}


Write-Host "`nKerberos Authentication Events (Last 10 Success + Last 10 Failures):" -ForegroundColor Cyan

$allKerberos = @()

# Kerberos Successes
$kerberosSuccess = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4768, 4769
} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
    $xml = [xml]$_.ToXml()
    $resultCode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' } | Select-Object -ExpandProperty '#text' -First 1
    $resultCode -eq '0x0' -or $resultCode -eq '0'
} | Select-Object -First 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $eventID = $_.Id
    $eventType = switch ($eventID) {
        4768 { 'Kerberos TGT Granted' }
        4769 { 'Kerberos Service Ticket' }
    }
    
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Status = 'SUCCESS'
        Type = $eventType
        User = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        Domain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        Reason = 'Granted'
        SourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    }
}
$allKerberos += $kerberosSuccess

# Kerberos Failures
$kerberosFailures = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4768, 4771, 4776
} -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
    $xml = [xml]$_.ToXml()
    $resultCode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' -or $_.Name -eq 'FailureCode' } | Select-Object -ExpandProperty '#text' -First 1
    $resultCode -ne '0x0' -and $resultCode -ne '0'
} | Select-Object -First 10 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    
    $eventID = $_.Id
    $eventType = switch ($eventID) {
        4768 { 'Kerberos TGT Request' }
        4771 { 'Kerberos Pre-Auth' }
        4776 { 'NTLM Auth' }
    }
    
    $failureCode = ($eventData | Where-Object { $_.Name -eq 'Status' -or $_.Name -eq 'FailureCode' }).'#text'
    $failureDesc = switch ($failureCode) {
        '0x6' { 'Bad username' }
        '0x7' { 'New computer joined domain' }
        '0x9' { 'Administrator intervention required' }
        '0xC' { 'Workstation restriction' }
        '0x12' { 'Account disabled/expired/locked' }
        '0x17' { 'Password expired' }
        '0x18' { 'Bad password' }
        '0x25' { 'Clock skew too great' }
        '0xC0000064' { 'User does not exist' }
        '0xC000006A' { 'Incorrect password' }
        '0xC0000234' { 'Account locked out' }
        default { $failureCode }
    }
    
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Status = 'FAILED'
        Type = $eventType
        User = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        Domain = ($eventData | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
        Reason = $failureDesc
        SourceIP = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    }
}
$allKerberos += $kerberosFailures

$allKerberos | Sort-Object Time -Descending | Format-Table -Property Time, Status, Type, User, Domain, Reason, SourceIP -Wrap | Out-String -Width 4096 -Stream | ForEach-Object {
    if ($_ -match 'SUCCESS') {
        Write-Host $_ -ForegroundColor Green
    } elseif ($_ -match 'FAILED') {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}