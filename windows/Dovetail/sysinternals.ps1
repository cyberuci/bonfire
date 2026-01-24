netsh a f a r n=WEB_OUT dir=out a=allow prot=TCP remoteport="80,443"

netsh a s a state on

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ProgressPreference = 'SilentlyContinue'

$destinationPath = "C:\Users\Administrator\Documents\Sysinternals.zip"
$extractedPath = "C:\Users\Administrator\Documents\Sysinternals"

Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -o $destinationPath -UseBasicParsing

Expand-Archive -Path $destinationPath -DestinationPath $extractedPath -ErrorAction SilentlyContinue

netsh a f del r n=WEB_OUT
