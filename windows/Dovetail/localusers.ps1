<#
.SYNOPSIS
    Performs a bulk password rotation for local user accounts on non-Domain Controller systems.

.DESCRIPTION
    This script identifies if the local system is a Domain Controller; if it is not, it 
    proceeds to rotate passwords for all enabled local user accounts. 

    Key features include:
    - Exclusion Logic: Specifically skips the 'Administrator' account, disabled accounts, 
      and a predefined 'hacker1' account.
    - Secure Generation: Uses a custom function to generate 10-character complex passwords 
      containing uppercase, lowercase, numbers, and special characters.
    - Logging: Records the new credentials in a CSV-formatted text file located in the 
      Administrator's Documents folder.
    - Safety Check: Automatically terminates if the system is identified as a Primary 
      or Backup Domain Controller to prevent unintended impact on domain accounts.
#>

$domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
if (!($domainRole -eq 4 -or $domainRole -eq 5)) {
    $hostname = $env:computername
    $outputFile = "C:\Users\Administrator\Documents\passwords_output_$($hostname).txt"

    function Generate-RandomPassword {
        $length = 10
        $upper   = (65..90   | ForEach-Object {[char]$_}) # A-Z
        $lower   = (97..122  | ForEach-Object {[char]$_}) # a-z
        $numbers = (48..57   | ForEach-Object {[char]$_}) # 0-9
        $special = "!@#$%^&*()-_=+[]{}<>?|".ToCharArray() # Special characters
        $all     = $upper + $lower + $numbers + $special
        $passwordArray = @(
            ($upper   | Get-Random -Count 1) +
            ($lower   | Get-Random -Count 1) +
            ($numbers | Get-Random -Count 1) +
            ($special | Get-Random -Count 1) +
            ($all     | Get-Random -Count ($length - 4))
        )
        $passwordArray    = $passwordArray -join ''
        $shuffledPassword = ($passwordArray.ToCharArray() | Sort-Object {Get-Random}) -join ''
        $finalPassword = $shuffledPassword -replace '\s', ''
        return $finalPassword
    }

    Set-Content -Path $outputFile -Value "Username,Password"

    Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True" | ForEach-Object {
        if ($_.Name -ne "Administrator" -and $_.Disabled -eq $false -and $_.Name -ne "hacker1") {
            try {
                $username = $_.Name
                $password = Generate-RandomPassword
                net user $username $password
                Write-Host "[$($hostname)] Changed password for $username" 
            }catch{
                Write-Host "[$($hostname)] Failed to change password for $username" -ForegroundColor Red
            }
            try{
                Add-Content -Path $outputFile -Value "$username,$password"
            }catch{
                Write-Host "[$($hostname)] Failed to write password in file for $username" -ForegroundColor Red
            }
            
        }
    }

    Write-Host "Password rotation complete. Output saved to $outputFile" -ForegroundColor Cyan
}
else {
    $hostname = $env:computername
    Write-Host "$hostname is a Domain Controller..."
}

