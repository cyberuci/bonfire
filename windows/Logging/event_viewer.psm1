function Get-FilteredEventLog {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$LogName,
        
        [Parameter(Mandatory=$true)]
        [string]$XmlFilter,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxEvents = 50,
        
        [Parameter(Mandatory=$false)]
        [string[]]$Fields = @('TimeCreated', 'Id', 'LevelDisplayName', 'ProviderName', 'Message')
    )
    
    try {
        Write-Host "`n=== Querying Event Logs ===" -ForegroundColor Cyan
        Write-Host "Max Events: $MaxEvents`n" -ForegroundColor Gray
        
        $events = Get-WinEvent -FilterXml $XmlFilter -MaxEvents $MaxEvents -ErrorAction Stop
        
        if ($events.Count -eq 0) {
            Write-Host "No events found matching the filter criteria." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Found $($events.Count) event(s)`n" -ForegroundColor Green
        
        $counter = 1
        foreach ($occurence in $events) {
            Write-Host "[$counter/$($events.Count)] " -NoNewline -ForegroundColor Magenta
            Write-Host ("=" * 80) -ForegroundColor DarkGray

            if ($PSBoundParameters.ContainsKey('Fields')) {
                $currentFields = $Fields
            } else {
                $currentFields = @('TimeCreated', 'Id', 'LevelDisplayName', 'ProviderName', 'Message')
            }
            
            foreach ($field in $currentFields) {
                $value = $occurence.$field

                $valueColor = 'White'
                if ($field -eq 'LevelDisplayName') {
                    $valueColor = switch ($value) {
                        'Error'    { 'Red' }
                        'Warning'  { 'Yellow' }
                        'Critical' { 'Magenta' }
                        'Information' { 'Green' }
                        default { 'White' }
                    }
                }

                Write-Host "  $field : " -NoNewline -ForegroundColor Cyan
                
                if ($null -eq $value) {
                    Write-Host "<NULL>" -ForegroundColor DarkGray
                } else {
                    Write-Host $value -ForegroundColor $valueColor
                }
            }
            Write-Host ("-" * 30) -ForegroundColor Gray
                        
            Write-Host ""
            $counter++
        }
        
        Write-Host ("=" * 80) -ForegroundColor DarkGray
        Write-Host "`nTotal Events Displayed: $($events.Count)" -ForegroundColor Cyan
        
    }
    catch {
        Write-Host "`nError querying event logs: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please verify your XML filter syntax and that you have appropriate permissions.`n" -ForegroundColor Yellow
    }
}

function New-EventLogXmlFilter {
   
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogName,
        
        [Parameter(Mandatory=$false)]
        [int]$EventId,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet(1,2,3,4)]
        [int]$Level,
        
        [Parameter(Mandatory=$false)]
        [int]$Hours = 24,
        
        [Parameter(Mandatory=$false)]
        [string]$ProviderName
    )
    
    $milliseconds = $Hours * 3600000
    $conditions = @()
    
    if ($Level) {
        $conditions += "Level=$Level"
    }
    
    if ($EventId) {
        $conditions += "EventID=$EventId"
    }
    
    if ($ProviderName) {
        $conditions += "Provider[@Name='$ProviderName']"
    }
    
    $conditions += "TimeCreated[timediff(@SystemTime) &lt;= $milliseconds]"
    
    $conditionString = $conditions -join " and "
    
    $xml = @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">*[System[$conditionString]]</Select>
  </Query>
</QueryList>
"@
    
    return $xml
}


Export-ModuleMember -Function Get-FilteredEventLog, New-EventLogXmlFilter