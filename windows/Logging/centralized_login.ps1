$Computers = @("", "")
$HistoryRoot = "C:\Monitoring\History"
$DetailDir = "C:\Monitoring\Details"
$Threshold = 1
$CycleMinutes = 1

$Queries = @{
    "Query1"    = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624)]]</Select></Query></QueryList>"
    "Query2" = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4769)]]</Select></Query></QueryList>"
    "Query3"   = "<QueryList><Query Id='0' Path='Security'><Select Path='Security'>*[System[(EventID=4624)]]</Select></Query></QueryList>"
}

foreach ($Path in @($HistoryRoot, $DetailDir)) { if (!(Test-Path $Path)) { New-Item $Path -ItemType Directory -Force | Out-Null } }

$SyncVars = [hashtable]::Synchronized(@{ 
    Data = [System.Collections.Generic.List[PSObject]]::new()
    Running = $true 
})

$BackgroundScript = {
    param($SyncVars, $Computers, $Queries, $HistoryRoot, $DetailDir, $Threshold, $CycleMinutes)
    
    while ($SyncVars.Running) {
        $ThisCycleResults = @()
        foreach ($IP in $Computers) {
            foreach ($QName in $Queries.Keys) {
                $HistFile = "$HistoryRoot\$IP-$QName.txt"
                $Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
                $CSVFile  = "$DetailDir\$IP-$QName-$Timestamp.csv"
                
                $Xml = [xml]$Queries[$QName]; $Log = $Xml.QueryList.Query.Path
                if (Test-Path $HistFile) { $LastID = Get-Content $HistFile -Raw } 
                else { 
                    try { $LastID = (Get-WinEvent -ComputerName $IP -LogName $Log -MaxEvents 1 -ErrorAction Stop).RecordId; $LastID | Set-Content $HistFile; continue } catch { continue }
                }
                
                $S = $Xml.CreateElement("Suppress"); $S.SetAttribute("Path", $Log); $S.InnerText = "*[System[(EventRecordID <= $LastID)]]"
                $null = $Xml.QueryList.Query.AppendChild($S)

                try {
                    $Events = Get-WinEvent -ComputerName $IP -FilterXml $Xml.OuterXml -ErrorAction SilentlyContinue
                    $ParsedEvents = @()

                    foreach ($occurrence in $Events) {
                        $fieldsFound = [ordered]@{
                            "TimeCreated"            = $occurrence.TimeCreated
                            "Account Name"           = $null
                            "Source Network Address" = $null
                            "EventID"                = $occurrence.Id
                            "TargetMachine"          = $occurrence.MachineName
                            "Source Port"            = $null
                            "Account Domain"         = $null
                            "Process Name"           = $null
                        }

                        foreach ($line in $occurrence.Message -split "`r?`n") {
                            if ($line -match '^\s*(?<Label>.+?):\s*(?<Value>.*)$') {
                                $key = $Matches['Label'].Trim(); $val = $Matches['Value'].Trim()
                                if ($val) { $fieldsFound[$key] = $val }
                            }
                        }

                        if ($fieldsFound["Account Name"] -like "*$") { 
                            continue 
                        }

                        if (-not $fieldsFound["Source Network Address"] -and $fieldsFound["Client Address"]) {
                            $fieldsFound["Source Network Address"] = $fieldsFound["Client Address"]
                        }
                        if (-not $fieldsFound["Source Port"] -and $fieldsFound["Client Port"]) {
                            $fieldsFound["Source Port"] = $fieldsFound["Client Port"]
                        }

                        for ($i=0; $i -lt $occurrence.Properties.Count; $i++) {
                            $propName = "RawProp_$i"
                            if (-not $fieldsFound.Contains($propName)) { $fieldsFound[$propName] = $occurrence.Properties[$i].Value }
                        }

                        $ParsedEvents += [PSCustomObject]$fieldsFound
                    }

                    if ($ParsedEvents.Count -gt 0) {
                        $Events[0].RecordId | Set-Content $HistFile
                        $ParsedEvents | Export-Csv $CSVFile -NoTypeInformation
                    } else {
                        try { $NewestID = (Get-WinEvent -ComputerName $IP -LogName $Log -MaxEvents 1).RecordId; $NewestID | Set-Content $HistFile } catch { }
                    }


                    $Result = [PSCustomObject]@{
                        Time      = Get-Date -Format "HH:mm:ss"
                        Computer  = $IP
                        Query     = $QName
                        Events    = $ParsedEvents.Count
                        Status    = if ($ParsedEvents.Count -gt $Threshold) { "!! SPIKE !!" } else { "Normal" }
                        CSVLink   = if ($ParsedEvents.Count -gt 0) { $CSVFile } else { $null }
                        IsDivider = $false
                    }

                    if ($ParsedEvents.Count -gt $Threshold) { msg * "ALERT: $($QName) spike on $($IP)! ($($ParsedEvents.Count) events)" }
                    $ThisCycleResults += $Result

                } catch { $ThisCycleResults += [PSCustomObject]@{ Time=$(Get-Date -Format "HH:mm:ss"); Computer=$IP; Query=$QName; Events="ERR"; Status="OFFLINE"; CSVLink=$null; IsDivider=$false } }
            }
        }
        
        $ThisCycleResults += [PSCustomObject]@{ Time="--------"; Computer="----------"; Query="----------"; Events="---"; Status="----------"; CSVLink=$null; IsDivider=$true }

        foreach ($Result in $ThisCycleResults) { $SyncVars.Data.Add($Result) }
        while ($SyncVars.Data.Count -gt 100) { $SyncVars.Data.RemoveAt(0) }

        Start-Sleep -Seconds ($CycleMinutes * 60)
    }
}

$Runspace = [PowerShell]::Create().AddScript($BackgroundScript).AddArgument($SyncVars).AddArgument($Computers).AddArgument($Queries).AddArgument($HistoryRoot).AddArgument($DetailDir).AddArgument($Threshold).AddArgument($CycleMinutes)
$Runspace.BeginInvoke()


$InputBuffer = ""
while ($true) {
    Clear-Host
    Write-Host "--- EVENT LOG COMMAND CENTER (Newest at Bottom) ---" -ForegroundColor Cyan
    Write-Host "Auto-Refreshing every 10s. Type Row ID and press Enter to drill down." -ForegroundColor Gray
    Write-Host "----------------------------------------------------------------------------------"

    $UIList = @()
    $CurrentData = $SyncVars.Data.ToArray()
    for ($i = 0; $i -lt $CurrentData.Count; $i++) {
        $item = $CurrentData[$i]
        $UIList += [PSCustomObject]@{
            ID       = if ($item.IsDivider) { "" } else { $i }
            Time     = $item.Time
            Computer = $item.Computer
            Query    = $item.Query
            Events   = $item.Events
            Status   = $item.Status
        }
    }
    $UIList | Format-Table -AutoSize
    Write-Host "`nSelection: $InputBuffer" -NoNewline

    $RefreshTimer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($RefreshTimer.Elapsed.TotalSeconds -lt 10) {
        if ([console]::KeyAvailable) {
            $Key = [console]::ReadKey($true)
            if ($Key.Key -eq "Enter") {
                if ($InputBuffer -match '^\d+$') {
                    $idx = [int]$InputBuffer
                    if ($idx -lt $SyncVars.Data.Count) {
                        $Target = $SyncVars.Data[$idx]
                        if ($Target.CSVLink -and (Test-Path $Target.CSVLink)) {
                            Import-Csv $Target.CSVLink | Out-GridView -Title "Events for $($Target.Computer) at $($Target.Time)"
                        }
                    }
                }
                $InputBuffer = ""; break 
            }
            elseif ($Key.Key -eq "Backspace") {
                if ($InputBuffer.Length -gt 0) { $InputBuffer = $InputBuffer.SubString(0, $InputBuffer.Length - 1) }
                Write-Host "`rSelection: $InputBuffer  " -NoNewline
            }
            else { $InputBuffer += $Key.KeyChar; Write-Host $Key.KeyChar -NoNewline }
        }
        Start-Sleep -Milliseconds 100
    }
}