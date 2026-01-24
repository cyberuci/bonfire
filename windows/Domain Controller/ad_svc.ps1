$LDAPServer = ""
$MaxEventCount = 100

$xmlQueries = @(
@"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[(EventID=4624)]]
    </Select>
  </Query>
</QueryList>
"@,

@"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[(EventID=4769)]]
    </Select>
  </Query>
</QueryList>
"@
)


$allEvents = @()
foreach ($xml in $xmlQueries) {
    $events = Get-WinEvent -ComputerName $LDAPServer -FilterXml $xml -MaxEvents $MaxEventCount

    foreach ($occurrence in $events) {
        $fieldsFound = [ordered]@{
            "TimeCreated"     = $occurrence.TimeCreated
            "TargetMachine"   = $occurrence.MachineName
            "EventID"         = $occurrence.Id
            "Source Network Address" = $null
            "Source Port"      = $null
            "Account Name"     = $null
            "Account Domain"   = $null
            "Process Name"     = $null
            "Logon Process"    = if ($occurrence.Properties.Count -gt 8) { $occurrence.Properties[8].Value } else { $null }
            "Authentication Package" = if ($occurrence.Properties.Count -gt 9) { $occurrence.Properties[9].Value } else { $null }
        }

        foreach ($line in $occurrence.Message -split "`r?`n") {
            if ($line -match '^\s*(?<Label>.+?):\s*(?<Value>.*)$') {
                $key = $Matches['Label'].Trim()
                $val = $Matches['Value'].Trim()
                if ($val) { $fieldsFound[$key] = $val }
            }
        }

        if (-not $fieldsFound["Source Network Address"] -and $fieldsFound["Client Address"]) {
            $fieldsFound["Source Network Address"] = $fieldsFound["Client Address"]
        }
        if (-not $fieldsFound["Source Port"] -and $fieldsFound["Client Port"]) {
            $fieldsFound["Source Port"] = $fieldsFound["Client Port"]
        }

        $allEvents += [PSCustomObject]$fieldsFound
    }
}

$allEvents = $allEvents | Where-Object { $_."Source Network Address" -ne $null }

$continue = $true
while ($continue -and $allEvents.Count -gt 0) {

    $eventIdSummary = $allEvents |
        Group-Object -Property EventID |
        Sort-Object Count -Descending |
        Select-Object @{Name='EventID';Expression={$_.Name}}, @{Name='EventCount';Expression={$_.Count}}

    $selectedEvent = $eventIdSummary | Out-GridView -Title "Select Event ID to drill down (Cancel to exit)" -PassThru
    if (-not $selectedEvent) { break }

    $eventId = $selectedEvent.EventID

    $ipsSummary = $allEvents |
        Where-Object { $_.EventID -eq $eventId } |
        Group-Object -Property "Source Network Address" |
        Sort-Object Count -Descending |
        Select-Object @{Name='SourceIP';Expression={$_.Name}}, @{Name='EventCount';Expression={$_.Count}}

    $selectedIP = $ipsSummary | Out-GridView -Title "Select Source IP(s) for Event ID $eventId (Cancel to go back)" -PassThru
    if (-not $selectedIP) { continue } 

    $ips = $selectedIP.SourceIP

    $allEvents |
        Where-Object { $_.EventID -eq $eventId -and $ips -contains $_."Source Network Address" } |
        Out-GridView -Title "Details for Event ID $eventId, IP(s): $($ips -join ', ')"

}
