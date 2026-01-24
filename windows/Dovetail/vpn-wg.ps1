# Run as Administrator
# .\wg-windows-installer.ps1 -configPath <PATH-TO-WG-CONFIG>

#Requires -RunAsAdministrator

param (
    [string[]]$configPath
)

# Check if WireGuard is already installed
if (-Not (Get-Command wireguard.exe -errorAction SilentlyContinue)) {
	Write-Host -ForegroundColor Yellow "Trying to download and install WireGuard..."
	
	try {
		Invoke-WebRequest https://download.wireguard.com/windows-client/wireguard-installer.exe -OutFile wg-installer.exe
		# TODO: Add temp firewall
		
		Write-Host -ForegroundColor Green "Finished downloading!"
		
		try {
			Write-Host -ForegroundColor Yellow "Launching installer..."
			Start-Process wg-installer.exe -Wait
			
			Write-Host -ForegroundColor Green "Done! Cleaning up installer!"
			Remove-Item wg-installer.exe
		} catch {
			Write-Host -ForegroundColor Red "Error installing!"
			return
		}
	} catch {
		Write-Host -ForegroundColor Red "Error downloading!"
		return
	}
} else {
	Write-Host -ForegroundColor Green "WireGuard is already installed!"
}

# "C:\Program Files\WireGuard\wireguard.exe" UDP inbound exception
# Get-NetFirewallRule -DisplayName "Allow Wireguard UDP Inbound"
# New-NetFirewallRule -DisplayName "Allow Wireguard UDP Inbound" -Direction Inbound -Program "C:\Program Files\WireGuard\wireguard.exe" -Action Allow
# This does not seem to be needed since it looks like Wireguard creates its own hidden firewall rules

# Install config from given path
if (-Not $configPath) {
	Write-Host -ForegroundColor Red "-configPath is empty! Configuration file not installed!"
	return
} else {
	Write-Host -ForegroundColor Yellow "Installing provided config..."

	Copy-Item "$configPath" -Destination "C:\Program Files\WireGuard\Data\Configurations"
	Invoke-Expression -Command "wireguard.exe /installtunnelservice '$configPath'"

	Write-Host -ForegroundColor Green "Done!"
}