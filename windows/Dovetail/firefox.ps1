<#
.SYNOPSIS
    Temporarily modifies the Windows Firewall to download the latest Firefox installer and then restores original settings.

.DESCRIPTION
    This script automates the retrieval of the Firefox web browser in a restricted environment. 
    It performs the following security and networking tasks:
    1. Creates a temporary outbound firewall rule allowing TCP traffic on ports 80 and 443.
    2. Ensures the Windows Firewall state is set to "On".
    3. Configures the session to use TLS 1.2 for secure communication.
    4. Downloads the 64-bit Firefox installer directly to the Administrator's Documents folder.
    5. Deletes the temporary firewall rule immediately after the download completes to maintain a hardened security posture.
#>

netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"

netsh a s a state on

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

Invoke-WebRequest "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US&attribution_code=c291cmNlPXd3dy5nb29nbGUuY29tJm1lZGl1bT1yZWZlcnJhbCZjYW1wYWlnbj0obm90IHNldCkmY29udGVudD0obm90IHNldCkmZXhwZXJpbWVudD0obm90IHNldCkmdmFyaWF0aW9uPShub3Qgc2V0KSZ1YT1jaHJvbWUmY2xpZW50X2lkX2dhND0obm90IHNldCkmc2Vzc2lvbl9pZD0obm90IHNldCkmZGxzb3VyY2U9bW96b3Jn&attribution_sig=8736a93bec69fc1c243683f991d9ab1e2e55c29d874ba87a68392df75ba4733f" -o "C:\Users\Administrator\Documents\Firefox.exe" -UseBasicParsing

netsh a f del r n=WEB_OUT
