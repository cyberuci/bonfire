$HistoryDir = "C:\Monitoring\Details"

Clear-Host
Write-Host "Reading history files from: $HistoryDir" -ForegroundColor Cyan

if (!(Test-Path $HistoryDir)) {
    Write-Warning "Directory not found. No history to display."
    exit
}

$Files = Get-ChildItem -Path $HistoryDir -Filter "*.csv" | Sort-Object LastWriteTime
$HistoryData = [System.Collections.Generic.List[PSObject]]::new()
$RowID = 0

$MaxCompLen  = 15
$MaxQueryLen = 15

foreach ($File in $Files) {
    Write-Progress -Activity "Loading History" -Status "Reading $($File.Name)" -PercentComplete (($RowID / $Files.Count) * 100)

    if ($File.BaseName -match '^([\d\.]+)-(.+)-(\d{8}_\d{4})$') {
        $IP      = $Matches[1]
        $Query   = $Matches[2]
        $TimeRaw = $Matches[3]

        if ($IP.Length -gt $MaxCompLen) { $MaxCompLen = $IP.Length }
        if ($Query.Length -gt $MaxQueryLen) { $MaxQueryLen = $Query.Length }

        try {
            $DT = [DateTime]::ParseExact($TimeRaw, "yyyyMMdd_HHmm", $null)
            $DisplayTime = $DT.ToString("yyyy-MM-dd HH:mm")
        } catch {
            $DisplayTime = $TimeRaw
        }

        $LineCount = (Get-Content $File.FullName | Measure-Object).Count - 1
        
        if ($LineCount -gt 0) {
            $HistoryData.Add([PSCustomObject]@{
                ID       = $RowID
                Time     = $DisplayTime
                Computer = $IP
                Query    = $Query
                Events   = $LineCount
                FullPath = $File.FullName
            })
            $RowID++
        }
    }
}
Write-Progress -Activity "Loading History" -Completed

$InputBuffer = ""

$wID    = 4
$wTime  = 18
$wComp  = $MaxCompLen + 2
$wQuery = $MaxQueryLen + 2
$wEvt   = 8

$DivLine = "+{0}+{1}+{2}+{3}+{4}+" -f ("-"*$wID), ("-"*$wTime), ("-"*$wComp), ("-"*$wQuery), ("-"*$wEvt)

while ($true) {
    Clear-Host
    Write-Host "--- HISTORY REPLAY MODE ---" -ForegroundColor Magenta
    Write-Host "Files Loaded: $($HistoryData.Count)" -ForegroundColor Gray
    Write-Host "Enter ID to view details. (Esc to Quit)" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host $DivLine -ForegroundColor DarkGray
    $HeaderFmt = "|{0,-$wID}|{1,-$wTime}|{2,-$wComp}|{3,-$wQuery}|{4,-$wEvt}|"
    Write-Host ($HeaderFmt -f " ID"," Time"," Computer"," Query"," Events") -ForegroundColor Cyan
    Write-Host $DivLine -ForegroundColor DarkGray

    foreach ($row in $HistoryData) {
        $RowFmt = "|{0,-$wID}|{1,-$wTime}|{2,-$wComp}|{3,-$wQuery}|{4,-$wEvt}|"
        
        $EvtColor = if ($row.Events -gt 10) { "Red" } elseif ($row.Events -gt 5) { "Yellow" } else { "Green" }
        
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-$wID}" -f $row.ID) -NoNewline -ForegroundColor White
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-$wTime}" -f $row.Time) -NoNewline -ForegroundColor Gray
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-$wComp}" -f $row.Computer) -NoNewline -ForegroundColor White
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-$wQuery}" -f $row.Query) -NoNewline -ForegroundColor White
        Write-Host "|" -NoNewline -ForegroundColor DarkGray
        Write-Host ("{0,-$wEvt}" -f $row.Events) -NoNewline -ForegroundColor $EvtColor
        Write-Host "|" -ForegroundColor DarkGray
        
        Write-Host $DivLine -ForegroundColor DarkGray
    }

    Write-Host "`nSelection (ID): $InputBuffer" -NoNewline
    
    while ($true) {
        if ([console]::KeyAvailable) {
            $Key = [console]::ReadKey($true)

            if ($Key.Key -eq "Enter") {
                if ($InputBuffer -match '^\d+$') {
                    $SelectedID = [int]$InputBuffer
                    $Target = $HistoryData | Where-Object { $_.ID -eq $SelectedID }

                    if ($Target) {
                        Write-Host "`nOpening GridView..." -ForegroundColor Yellow
                        $CsvData = Import-Csv $Target.FullPath
                        $CsvData | Out-GridView -Title "$($Target.Computer) | $($Target.Query) | $($Target.Events) Events"
                    }
                }
                $InputBuffer = ""
                break 
            }
            elseif ($Key.Key -eq "Backspace") {
                if ($InputBuffer.Length -gt 0) {
                    $InputBuffer = $InputBuffer.SubString(0, $InputBuffer.Length - 1)
                }
                Write-Host "`rSelection (ID): $InputBuffer   " -NoNewline
            }
            elseif ($Key.Key -eq "Escape") {
                Clear-Host; exit
            }
            else {
                $InputBuffer += $Key.KeyChar
                Write-Host $Key.KeyChar -NoNewline
            }
        }
        Start-Sleep -Milliseconds 50
    }
}